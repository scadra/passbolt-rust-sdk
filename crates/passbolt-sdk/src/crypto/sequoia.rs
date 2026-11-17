// Passbolt ~ Open source password manager for teams
// Copyright (c) Passbolt SA (https://www.passbolt.com)
//
// Licensed under GNU Affero General Public License version 3 of the or any later version.
// For full copyright and license information, please see the LICENSE
// Redistributions of files must retain the above copyright notice.
//
// @copyright     Copyright (c) Passbolt SA (https://www.passbolt.com)
// @license       https://opensource.org/licenses/AGPL-3.0 AGPL License
// @link          https://www.passbolt.com Passbolt(tm)
// @since         0.1.0

//! The Sequoia engine, on Nettle.
//!
//! A private key is unlocked once per passphrase, until its last handle is dropped. The GnuPG
//! AEAD (OCB) container is not read: Sequoia reads SEIPD v1 and v2 only.

use std::io::Write;
use std::sync::{Arc, Mutex};

use sequoia_openpgp::cert::prelude::*;
use sequoia_openpgp::crypto::{self as sq_crypto, Password};
use sequoia_openpgp::packet::key::{SecretParts, UnspecifiedRole};
use sequoia_openpgp::packet::signature::SignatureBuilder;
use sequoia_openpgp::packet::{Key, PKESK, SKESK};
use sequoia_openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, MessageStructure, VerificationHelper,
};
use sequoia_openpgp::parse::{PacketParser, Parse};
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::stream::{
    Armorer, Encryptor, LiteralWriter, Message, Recipient, Signer as MessageSigner,
};
use sequoia_openpgp::types::{
    DataFormat, HashAlgorithm, KeyFlags, RevocationStatus, SignatureType, SymmetricAlgorithm,
};
use sequoia_openpgp::{Cert, Packet};
use sha2::{Digest, Sha256};

use super::{key_of, ready, CryptoFuture, Engine, KeyHandle, SessionKey};
use crate::error::CryptoError;

/// What keys are checked against: Sequoia's standard policy.
static POLICY: StandardPolicy<'static> = StandardPolicy::new();

/// The Sequoia engine.
pub struct Sequoia;

/// A private key, and its secrets once unlocked.
struct PrivateKey {
    cert: Cert,
    unlocked: Mutex<Option<Unlocked>>,
}

/// The secrets of a private key, and the digest of the passphrase that unlocked them.
struct Unlocked {
    passphrase: [u8; 32],
    keys: Vec<Key<SecretParts, UnspecifiedRole>>,
}

impl PrivateKey {
    /// Its secret keys, unlocked with `passphrase`; refused when it does not unlock them.
    fn unlock(&self, passphrase: &str) -> Result<Vec<Key<SecretParts, UnspecifiedRole>>, String> {
        let digest: [u8; 32] = Sha256::digest(passphrase.as_bytes()).into();
        let mut unlocked = self
            .unlocked
            .lock()
            .map_err(|_| "the unlocked keys are unusable".to_owned())?;
        if let Some(held) = unlocked.as_ref().filter(|held| held.passphrase == digest) {
            return Ok(held.keys.clone());
        }
        let password = Password::from(passphrase);
        let keys = self
            .cert
            .keys()
            .secret()
            .map(|amalgamation| {
                let key = amalgamation.key().clone();
                if key.has_unencrypted_secret() {
                    return Ok(key);
                }
                key.decrypt_secret(&password)
                    .map_err(|error| format!("unlock key: {error}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        *unlocked = Some(Unlocked {
            passphrase: digest,
            keys: keys.clone(),
        });
        Ok(keys)
    }
}

impl Engine for Sequoia {
    fn name(&self) -> &'static str {
        "sequoia"
    }

    fn parse_private_key(&self, armored: &str) -> Result<(KeyHandle, String), CryptoError> {
        let cert = parse_cert(armored, "private key")?;
        if !cert.is_tsk() {
            return Err(CryptoError::KeyParse("private key: no secret key".into()));
        }
        let fingerprint = cert.fingerprint().to_hex();
        let key = PrivateKey {
            cert,
            unlocked: Mutex::new(None),
        };
        Ok((Arc::new(key), fingerprint))
    }

    fn parse_public_key(&self, armored: &str) -> Result<(KeyHandle, String), CryptoError> {
        let cert = parse_cert(armored, "public key")?;
        if cert.is_tsk() {
            return Err(CryptoError::KeyParse("public key: a private key".into()));
        }
        let fingerprint = cert.fingerprint().to_hex();
        Ok((Arc::new(cert), fingerprint))
    }

    fn decrypt<'a>(
        &'a self,
        armored_message: &'a str,
        private_key: &'a KeyHandle,
        passphrase: &'a str,
    ) -> CryptoFuture<'a, Vec<u8>> {
        ready(key_of(private_key).and_then(|key: &PrivateKey| {
            let helper = Helper::with_keys(key.unlock(passphrase).map_err(CryptoError::Decrypt)?);
            decrypt(armored_message, helper).map(|(plaintext, _)| plaintext)
        }))
    }

    fn decrypt_keeping_session_key<'a>(
        &'a self,
        armored_message: &'a str,
        private_key: &'a KeyHandle,
        passphrase: &'a str,
    ) -> CryptoFuture<'a, (Vec<u8>, SessionKey)> {
        ready(key_of(private_key).and_then(|key: &PrivateKey| {
            let helper = Helper::with_keys(key.unlock(passphrase).map_err(CryptoError::Decrypt)?);
            let (plaintext, helper) = decrypt(armored_message, helper)?;
            let session_key = helper
                .session_key
                .ok_or_else(|| CryptoError::Decrypt("no session key for this key".into()))?;
            Ok((plaintext, session_key))
        }))
    }

    fn decrypt_with_session_key<'a>(
        &'a self,
        armored_message: &'a str,
        session_key: &'a SessionKey,
    ) -> CryptoFuture<'a, Vec<u8>> {
        let helper = Helper {
            given: Some(session_key.clone()),
            ..Helper::default()
        };
        ready(decrypt(armored_message, helper).map(|(plaintext, _)| plaintext))
    }

    fn encrypt<'a>(
        &'a self,
        plaintext: &'a [u8],
        recipients: &'a [&'a KeyHandle],
    ) -> CryptoFuture<'a, String> {
        ready(
            public_keys(recipients)
                .and_then(|certs| encrypt(plaintext, DataFormat::Binary, Vec::new(), &certs)),
        )
    }

    fn sign_and_encrypt<'a>(
        &'a self,
        plaintext: &'a str,
        signers: &'a [(&'a KeyHandle, &'a str)],
        recipients: &'a [&'a KeyHandle],
    ) -> CryptoFuture<'a, String> {
        let signed = || {
            let signing_keys = signers
                .iter()
                .map(|(handle, passphrase)| {
                    let key: &PrivateKey = key_of(handle)?;
                    signing_key(key, passphrase)
                })
                .collect::<Result<Vec<_>, CryptoError>>()?;
            // UTF-8 literals are written with CR LF line endings.
            let text = plaintext.replace("\r\n", "\n").replace('\n', "\r\n");
            encrypt(
                text.as_bytes(),
                DataFormat::Unicode,
                signing_keys,
                &public_keys(recipients)?,
            )
        };
        ready(signed())
    }
}

fn public_keys<'a>(handles: &[&'a KeyHandle]) -> Result<Vec<&'a Cert>, CryptoError> {
    handles.iter().map(|handle| key_of(handle)).collect()
}

fn parse_cert(armored: &str, what: &str) -> Result<Cert, CryptoError> {
    Cert::from_bytes(armored.as_bytes())
        .map_err(|error| CryptoError::KeyParse(format!("{what}: {error}")))
}

/// The primary key of `key`, unlocked: Passbolt clients sign with it.
fn signing_key(key: &PrivateKey, passphrase: &str) -> Result<sq_crypto::KeyPair, CryptoError> {
    let failure = |reason: String| CryptoError::Encrypt(reason);
    let primary = key.cert.fingerprint();
    key.unlock(passphrase)
        .map_err(failure)?
        .into_iter()
        .find(|unlocked| unlocked.fingerprint() == primary)
        .ok_or_else(|| failure("no secret primary key".into()))?
        .into_keypair()
        .map_err(|error| failure(error.to_string()))
}

/// What the decryption of one message needs and learns.
#[derive(Default)]
struct Helper {
    keys: Vec<Key<SecretParts, UnspecifiedRole>>,
    /// The session key to decrypt with, instead of the keys.
    given: Option<SessionKey>,
    /// The session key the message was decrypted with.
    session_key: Option<SessionKey>,
    /// Whether the literal is text.
    is_text: bool,
}

impl Helper {
    fn with_keys(keys: Vec<Key<SecretParts, UnspecifiedRole>>) -> Self {
        Self {
            keys,
            ..Self::default()
        }
    }
}

impl VerificationHelper for Helper {
    fn inspect(&mut self, packet_parser: &PacketParser) -> sequoia_openpgp::Result<()> {
        if let Packet::Literal(literal) = &packet_parser.packet {
            #[allow(deprecated)] // `Text` is still read
            let is_text = matches!(literal.format(), DataFormat::Unicode | DataFormat::Text);
            self.is_text = is_text;
        }
        Ok(())
    }

    fn get_certs(
        &mut self,
        _ids: &[sequoia_openpgp::KeyHandle],
    ) -> sequoia_openpgp::Result<Vec<Cert>> {
        Ok(Vec::new())
    }

    /// Signatures are not checked, as with the other engines.
    fn check(&mut self, _structure: MessageStructure) -> sequoia_openpgp::Result<()> {
        Ok(())
    }
}

impl DecryptionHelper for Helper {
    fn decrypt(
        &mut self,
        pkesks: &[PKESK],
        _skesks: &[SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &sq_crypto::SessionKey) -> bool,
    ) -> sequoia_openpgp::Result<Option<Cert>> {
        if let Some(given) = &self.given {
            let key = sq_crypto::SessionKey::from(given.key());
            if decrypt(Some(SymmetricAlgorithm::from(given.algorithm())), &key) {
                return Ok(None);
            }
            return Err(refused("the session key does not decrypt this message"));
        }
        for pkesk in pkesks {
            for key in &self.keys {
                if !pkesk
                    .recipient()
                    .is_none_or(|recipient| recipient.aliases(key.key_handle()))
                {
                    continue;
                }
                let Ok(mut keypair) = key.clone().into_keypair() else {
                    continue;
                };
                let Some((algorithm, session_key)) = pkesk.decrypt(&mut keypair, sym_algo) else {
                    continue;
                };
                if !decrypt(algorithm, &session_key) {
                    continue;
                }
                // A SEIPD v2 session key carries no algorithm: the container gives it.
                if let Some(algorithm) = algorithm.or(sym_algo) {
                    self.session_key = Some(SessionKey::new(
                        u8::from(algorithm),
                        session_key.as_ref().to_vec(),
                    ));
                }
                return Ok(None);
            }
        }
        Err(refused("no session key for this key"))
    }
}

fn refused(reason: &str) -> sequoia_openpgp::anyhow::Error {
    sequoia_openpgp::Error::InvalidOperation(reason.into()).into()
}

/// Decrypt `armored_message` with `helper`; the plaintext, text with LF line endings, as
/// OpenPGP.js reads it.
fn decrypt(armored_message: &str, helper: Helper) -> Result<(Vec<u8>, Helper), CryptoError> {
    let failure = |error: sequoia_openpgp::anyhow::Error| CryptoError::Decrypt(error.to_string());
    let mut decryptor = DecryptorBuilder::from_bytes(armored_message.as_bytes())
        .map_err(failure)?
        .with_policy(&POLICY, None, helper)
        .map_err(failure)?;
    let mut data = Vec::new();
    std::io::copy(&mut decryptor, &mut data)
        .map_err(|error| CryptoError::Decrypt(format!("read: {error}")))?;
    let helper = decryptor.into_helper();
    if !helper.is_text {
        return Ok((data, helper));
    }
    let data = String::from_utf8(data)
        .map_or_else(std::string::FromUtf8Error::into_bytes, |text| {
            text.replace("\r\n", "\n").into_bytes()
        });
    Ok((data, helper))
}

/// The key a message for `cert` is encrypted with, as `OpenPGP.js` chooses it: the newest valid
/// subkey flagged for encryption, else the primary key. A revoked or expired key is refused,
/// like the browser extension refuses it.
fn recipient(cert: &Cert) -> Result<Recipient<'_>, CryptoError> {
    let fingerprint = cert.fingerprint().to_hex();
    let failure = |reason: &str| CryptoError::Encrypt(format!("key {fingerprint} {reason}"));
    if let RevocationStatus::Revoked(_) = cert.revocation_status(&POLICY, None) {
        return Err(failure("is revoked"));
    }
    let valid = cert
        .with_policy(&POLICY, None)
        .map_err(|error| failure(&format!("is not valid: {error}")))?;
    valid.alive().map_err(|_| failure("is expired"))?;
    let candidates = valid.keys().supported().alive().revoked(false).key_flags(
        KeyFlags::empty()
            .set_transport_encryption()
            .set_storage_encryption(),
    );
    let (subkeys, primary): (Vec<_>, Vec<_>) =
        candidates.partition(|amalgamation| !amalgamation.primary());
    subkeys
        .into_iter()
        .max_by_key(|amalgamation| amalgamation.key().creation_time())
        .or_else(|| primary.into_iter().next())
        .map(Recipient::from)
        .ok_or_else(|| failure("has no valid encryption key"))
}

fn encrypt(
    data: &[u8],
    format: DataFormat,
    signers: Vec<sq_crypto::KeyPair>,
    recipients: &[&Cert],
) -> Result<String, CryptoError> {
    let failure = |error: sequoia_openpgp::anyhow::Error| CryptoError::Encrypt(error.to_string());
    let recipients = recipients
        .iter()
        .map(|cert| recipient(cert))
        .collect::<Result<Vec<_>, _>>()?;
    if recipients.is_empty() {
        return Err(CryptoError::Encrypt("no recipient".into()));
    }
    let mut sink = Vec::new();
    {
        let message = Armorer::new(Message::new(&mut sink))
            .build()
            .map_err(failure)?;
        let mut message = Encryptor::for_recipients(message, recipients)
            .build()
            .map_err(failure)?;
        let mut signers = signers.into_iter();
        if let Some(first) = signers.next() {
            // Every signature covers the literal data, as OpenPGP.js and gopenpgp write them.
            let mut signer = MessageSigner::with_template(
                message,
                first,
                SignatureBuilder::new(SignatureType::Text),
            )
            .and_then(|signer| signer.hash_algo(HashAlgorithm::SHA256))
            .map_err(failure)?;
            for other in signers {
                signer = signer.add_signer(other).map_err(failure)?;
            }
            message = signer.build().map_err(failure)?;
        }
        let mut literal = LiteralWriter::new(message)
            .format(format)
            .build()
            .map_err(failure)?;
        literal
            .write_all(data)
            .map_err(|error| CryptoError::Encrypt(error.to_string()))?;
        literal.finalize().map_err(failure)?;
    }
    String::from_utf8(sink).map_err(|error| CryptoError::Encrypt(error.to_string()))
}
