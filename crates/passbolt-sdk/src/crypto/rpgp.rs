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

//! The rpgp engine, in Rust.

use std::sync::Arc;

use pgp::composed::{
    ArmorOptions, DecryptionOptions, Deserializable, DummyReader, Edata, Encryption, Message,
    MessageBuilder, PlainSessionKey, RawSessionKey, SignedPublicKey, SignedSecretKey, TheRing,
};
use pgp::crypto::aead::{AeadAlgorithm, ChunkSize};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::{DataMode, Features, ProtectedDataConfig, SymEncryptedProtectedDataConfig};
use pgp::types::{DecryptionKey, EskType, KeyDetails, KeyVersion, Password, PkeskVersion};

use super::{key_of, Engine, KeyHandle, SessionKey};
use crate::error::CryptoError;

/// The rpgp engine, the default one.
pub struct Rpgp;

impl Engine for Rpgp {
    fn name(&self) -> &'static str {
        "rpgp"
    }

    fn parse_private_key(&self, armored: &str) -> Result<(KeyHandle, String), CryptoError> {
        let key = parse_private_key(armored)?;
        let fingerprint = hex::encode_upper(key.fingerprint().as_bytes());
        Ok((Arc::new(key), fingerprint))
    }

    fn parse_public_key(&self, armored: &str) -> Result<(KeyHandle, String), CryptoError> {
        let key = parse_public_key(armored)?;
        let fingerprint = hex::encode_upper(key.fingerprint().as_bytes());
        Ok((Arc::new(key), fingerprint))
    }

    fn decrypt(
        &self,
        armored_message: &str,
        private_key: &KeyHandle,
        passphrase: &str,
    ) -> Result<Vec<u8>, CryptoError> {
        decrypt_message(armored_message, key_of(private_key)?, passphrase)
    }

    fn decrypt_keeping_session_key(
        &self,
        armored_message: &str,
        private_key: &KeyHandle,
        passphrase: &str,
    ) -> Result<(Vec<u8>, SessionKey), CryptoError> {
        decrypt_message_keeping_session_key(armored_message, key_of(private_key)?, passphrase)
    }

    fn decrypt_with_session_key(
        &self,
        armored_message: &str,
        session_key: &SessionKey,
    ) -> Result<Vec<u8>, CryptoError> {
        decrypt_with_session_key(armored_message, session_key)
    }

    fn encrypt(&self, plaintext: &[u8], recipients: &[&KeyHandle]) -> Result<String, CryptoError> {
        encrypt_message(plaintext, &public_keys(recipients)?)
    }

    fn sign_and_encrypt(
        &self,
        plaintext: &str,
        signers: &[(&KeyHandle, &str)],
        recipients: &[&KeyHandle],
    ) -> Result<String, CryptoError> {
        let signers = signers
            .iter()
            .map(|(key, passphrase)| {
                Ok(SigningKey {
                    key: key_of(key)?,
                    passphrase,
                })
            })
            .collect::<Result<Vec<_>, CryptoError>>()?;
        sign_and_encrypt(plaintext, &signers, &public_keys(recipients)?)
    }
}

fn public_keys<'a>(handles: &[&'a KeyHandle]) -> Result<Vec<&'a SignedPublicKey>, CryptoError> {
    handles.iter().map(|handle| key_of(handle)).collect()
}

/// Parse and validate a PGP private key from ASCII-armored text.
fn parse_private_key(armored: &str) -> Result<SignedSecretKey, CryptoError> {
    let (key, _) = SignedSecretKey::from_armor_single(armored.as_bytes())
        .map_err(|error| CryptoError::KeyParse(format!("private key: {error}")))?;
    key.verify_bindings()
        .map_err(|error| CryptoError::KeyParse(format!("private key verification: {error}")))?;
    Ok(key)
}

/// Parse a PGP public key from ASCII-armored text.
fn parse_public_key(armored: &str) -> Result<SignedPublicKey, CryptoError> {
    let (key, _) = SignedPublicKey::from_armor_single(armored.as_bytes())
        .map_err(|error| CryptoError::KeyParse(format!("public key: {error}")))?;
    key.verify_bindings()
        .map_err(|error| CryptoError::KeyParse(format!("public key verification: {error}")))?;
    Ok(key)
}

fn decrypt_message(
    armored_message: &str,
    private_key: &SignedSecretKey,
    passphrase: &str,
) -> Result<Vec<u8>, CryptoError> {
    let password = Password::from(passphrase);
    let ring = TheRing {
        secret_keys: vec![private_key],
        key_passwords: vec![&password],
        ..TheRing::default()
    };
    content(decrypt(parse_message(armored_message)?, ring)?)
}

/// Decrypt `message` with what `ring` holds. Besides SEIPD v1 and v2, the GnuPG AEAD (OCB)
/// container is read: the server encrypts with GnuPG, which uses it for keys that ask for it.
fn decrypt<'a>(message: Message<'a>, mut ring: TheRing<'_>) -> Result<Message<'a>, CryptoError> {
    ring.decrypt_options = DecryptionOptions::new().enable_gnupg_aead();
    message
        .decrypt_the_ring(ring, true)
        .map(|(decrypted, _)| decrypted)
        .map_err(|error| CryptoError::Decrypt(error.to_string()))
}

/// The symmetric algorithm of a SEIPD v2 (AEAD) message, whose session key has no algorithm;
/// `None` for the other containers.
fn seipd_v2_algorithm(message: &Message<'_>) -> Option<SymmetricKeyAlgorithm> {
    let Message::Encrypted {
        edata: Edata::SymEncryptedProtectedData { reader },
        ..
    } = message
    else {
        return None;
    };
    match reader.config() {
        ProtectedDataConfig::Seipd(SymEncryptedProtectedDataConfig::V2 { sym_alg, .. }) => {
            Some(*sym_alg)
        }
        _ => None,
    }
}

/// The key to decrypt `message` with: SEIPD v2 session keys carry no algorithm.
fn plain_session_key(session_key: &SessionKey, message: &Message<'_>) -> PlainSessionKey {
    let key = RawSessionKey::from(session_key.key().to_vec());
    if seipd_v2_algorithm(message).is_some() {
        PlainSessionKey::V6 { key }
    } else {
        PlainSessionKey::V3_4 {
            sym_alg: session_key.algorithm().into(),
            key,
        }
    }
}

fn decrypt_message_keeping_session_key(
    armored_message: &str,
    private_key: &SignedSecretKey,
    passphrase: &str,
) -> Result<(Vec<u8>, SessionKey), CryptoError> {
    let failure = |reason: String| CryptoError::Decrypt(reason);
    let message = parse_message(armored_message)?;
    let Message::Encrypted { esk, .. } = &message else {
        return Err(failure("not an encrypted message".into()));
    };
    let password = Password::from(passphrase);
    let decrypt_with = |key: &dyn DecryptionKey,
                        pkesk: &pgp::packet::PublicKeyEncryptedSessionKey| {
        let typ = match pkesk.version() {
            PkeskVersion::V3 => EskType::V3_4,
            PkeskVersion::V6 => EskType::V6,
            PkeskVersion::Other(_) => return None,
        };
        let values = pkesk.values().ok()?;
        key.decrypt(&password, values, typ).ok()?.ok()
    };
    let plain_key = esk
        .iter()
        .filter_map(|esk| match esk {
            pgp::composed::Esk::PublicKeyEncryptedSessionKey(pkesk) => Some(pkesk),
            pgp::composed::Esk::SymKeyEncryptedSessionKey(_) => None,
        })
        .find_map(|pkesk| {
            if pkesk.match_identity(private_key.primary_key.public_key()) {
                return decrypt_with(&private_key.primary_key, pkesk);
            }
            let subkey = private_key
                .secret_subkeys
                .iter()
                .find(|subkey| pkesk.match_identity(subkey.key.public_key()))?;
            decrypt_with(&subkey.key, pkesk)
        })
        .ok_or_else(|| failure("no session key for this key".into()))?;
    let (algorithm, key) = match &plain_key {
        PlainSessionKey::V3_4 { sym_alg, key } => (*sym_alg, key),
        PlainSessionKey::V6 { key } => (
            seipd_v2_algorithm(&message)
                .ok_or_else(|| failure("a v6 session key outside SEIPD v2".into()))?,
            key,
        ),
        PlainSessionKey::V5 { .. } => {
            return Err(failure("unsupported session key version".into()))
        }
    };
    let session_key = SessionKey::new(u8::from(algorithm), key.as_ref().to_vec());
    let ring = TheRing {
        session_keys: vec![plain_key],
        ..TheRing::default()
    };
    Ok((content(decrypt(message, ring)?)?, session_key))
}

fn decrypt_with_session_key(
    armored_message: &str,
    session_key: &SessionKey,
) -> Result<Vec<u8>, CryptoError> {
    let message = parse_message(armored_message)?;
    let ring = TheRing {
        session_keys: vec![plain_session_key(session_key, &message)],
        ..TheRing::default()
    };
    content(decrypt(message, ring)?)
}

fn parse_message(armored_message: &str) -> Result<Message<'_>, CryptoError> {
    Message::from_armor(armored_message.as_bytes())
        .map(|(message, _)| message)
        .map_err(|error| CryptoError::Decrypt(format!("parse message: {error}")))
}

/// The literal content of a decrypted message, decompressed (GnuPG, the Passbolt server,
/// compresses by default). Text keeps the LF line endings it was written with, as OpenPGP.js
/// reads it: the literal carries CR LF.
fn content(mut message: Message<'_>) -> Result<Vec<u8>, CryptoError> {
    if message.is_compressed() {
        message = message
            .decompress()
            .map_err(|error| CryptoError::Decrypt(format!("decompress: {error}")))?;
    }
    let is_text = message
        .literal_data_header()
        .is_some_and(|header| matches!(header.mode(), DataMode::Utf8 | DataMode::Text));
    let data = message
        .as_data_vec()
        .map_err(|error| CryptoError::Decrypt(format!("read: {error}")))?;
    if !is_text {
        return Ok(data);
    }
    Ok(
        String::from_utf8(data).map_or_else(std::string::FromUtf8Error::into_bytes, |text| {
            text.replace("\r\n", "\n").into_bytes()
        }),
    )
}

fn encrypt_message(
    plaintext: &[u8],
    recipients: &[&SignedPublicKey],
) -> Result<String, CryptoError> {
    encrypt(plaintext.to_vec(), DataMode::Binary, &[], recipients)
}

/// A private key and its passphrase.
struct SigningKey<'a> {
    key: &'a SignedSecretKey,
    passphrase: &'a str,
}

fn sign_and_encrypt(
    plaintext: &str,
    signers: &[SigningKey<'_>],
    recipients: &[&SignedPublicKey],
) -> Result<String, CryptoError> {
    // UTF-8 literals are written with CR LF line endings.
    let text = plaintext.replace("\r\n", "\n").replace('\n', "\r\n");
    encrypt(text.into_bytes(), DataMode::Utf8, signers, recipients)
}

/// One session key packet per recipient key, primary key or subkey, whichever the SEIPD
/// version of `builder`.
macro_rules! encrypt_to_each {
    ($builder:ident, $keys:expr, $rng:expr) => {
        for key in $keys {
            match key {
                EncryptionKey::Subkey(subkey) => $builder.encrypt_to_key($rng, *subkey),
                EncryptionKey::Primary(primary_key) => $builder.encrypt_to_key($rng, *primary_key),
            }
            .map_err(|error| CryptoError::Encrypt(error.to_string()))?;
        }
    };
}

fn encrypt(
    data: Vec<u8>,
    mode: DataMode,
    signers: &[SigningKey<'_>],
    recipients: &[&SignedPublicKey],
) -> Result<String, CryptoError> {
    let now = chrono::Utc::now();
    let keys = recipients
        .iter()
        .map(|recipient| encryption_key(recipient, &now))
        .collect::<Result<Vec<_>, _>>()?;
    let mut rng = rand::thread_rng();
    let builder = MessageBuilder::from_bytes("", data);
    if let Some((algorithm, aead)) = aead_cipher_suite(recipients) {
        let mut builder = builder.seipd_v2(&mut rng, algorithm, aead, AEAD_CHUNK_SIZE);
        encrypt_to_each!(builder, &keys, &mut rng);
        return sign_and_armor(builder, mode, signers);
    }
    let mut builder = builder.seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
    encrypt_to_each!(builder, &keys, &mut rng);
    sign_and_armor(builder, mode, signers)
}

fn sign_and_armor<'a, E: Encryption>(
    mut builder: MessageBuilder<'a, DummyReader, E>,
    mode: DataMode,
    signers: &[SigningKey<'a>],
) -> Result<String, CryptoError> {
    builder
        .data_mode(mode)
        .map_err(|error| CryptoError::Encrypt(error.to_string()))?;
    if mode == DataMode::Utf8 {
        builder.sign_text();
    }
    for signer in signers {
        builder.sign(
            &signer.key.primary_key,
            Password::from(signer.passphrase),
            HashAlgorithm::Sha256,
        );
    }
    builder
        .to_armored_string(rand::thread_rng(), ArmorOptions::default())
        .map_err(|error| CryptoError::Encrypt(format!("armor: {error}")))
}

/// The chunk size OpenPGP.js writes SEIPD v2 with.
const AEAD_CHUNK_SIZE: ChunkSize = ChunkSize::C256KiB;

/// The SEIPD v2 cipher suite of a message for `recipients`, as `OpenPGP.js` and gopenpgp choose
/// it: only when every key asks for SEIPD v2, the first suite they all prefer, else AES-128 OCB,
/// which every SEIPD v2 reader supports. `None` writes SEIPD v1.
fn aead_cipher_suite(
    recipients: &[&SignedPublicKey],
) -> Option<(SymmetricKeyAlgorithm, AeadAlgorithm)> {
    use SymmetricKeyAlgorithm::{AES128, AES256};
    const DESIRED: [(SymmetricKeyAlgorithm, AeadAlgorithm); 3] = [
        (AES256, AeadAlgorithm::Gcm),
        (AES256, AeadAlgorithm::Ocb),
        (AES128, AeadAlgorithm::Gcm),
    ];
    let preferences = recipients
        .iter()
        .map(|recipient| primary_self_signature(recipient))
        .collect::<Option<Vec<_>>>()?;
    let seipd_v2 = !preferences.is_empty()
        && preferences
            .iter()
            .all(|signature| signature.features().is_some_and(Features::seipd_v2));
    if !seipd_v2 {
        return None;
    }
    let preferred_by_all = DESIRED.into_iter().find(|suite| {
        preferences
            .iter()
            .all(|signature| signature.preferred_aead_algs().contains(suite))
    });
    Some(preferred_by_all.unwrap_or((AES128, AeadAlgorithm::Ocb)))
}

/// The self-signature holding the preferences of `key`: the direct key signature of a v6 key,
/// else the newest certification of its primary user ID (of any user ID if none is primary).
fn primary_self_signature(key: &SignedPublicKey) -> Option<&pgp::packet::Signature> {
    let newest = |signature: &&pgp::packet::Signature| {
        signature.created().map(pgp::types::Timestamp::as_secs)
    };
    if key.primary_key.version() == KeyVersion::V6 {
        return key.details.direct_signatures.iter().max_by_key(newest);
    }
    key.details
        .users
        .iter()
        .flat_map(|user| &user.signatures)
        .max_by_key(|signature| (signature.is_primary(), newest(signature)))
}

/// The key a message for `key` is encrypted with.
enum EncryptionKey<'a> {
    Subkey(&'a pgp::packet::PublicSubkey),
    Primary(&'a pgp::packet::PublicKey),
}

/// What a message for `key` is encrypted with at `now`, as `OpenPGP.js` chooses it: the newest
/// valid subkey flagged for encryption, else the primary key when it may encrypt. A revoked or
/// expired key is refused, like the browser extension refuses it.
fn encryption_key<'a>(
    key: &'a SignedPublicKey,
    now: &chrono::DateTime<chrono::Utc>,
) -> Result<EncryptionKey<'a>, CryptoError> {
    use pgp::packet::{Signature, SignatureType, SubpacketData};

    let now = now.timestamp();
    let fingerprint = hex::encode_upper(key.fingerprint().as_bytes());
    if !key.details.revocation_signatures.is_empty() {
        return Err(CryptoError::Encrypt(format!(
            "key {fingerprint} is revoked"
        )));
    }
    let self_signatures: Vec<&Signature> = key
        .details
        .users
        .iter()
        .flat_map(|user| &user.signatures)
        .chain(&key.details.direct_signatures)
        .collect();
    // The longest validity its self-signatures give, from its creation.
    let validity = self_signatures
        .iter()
        .filter_map(|signature| signature.key_expiration_time())
        .map(|validity| i64::from(validity.as_secs()))
        .max();
    let created = i64::from(key.primary_key.created_at().as_secs());
    if let Some(expires_at) = validity
        .map(|validity| created + validity)
        .filter(|expires_at| *expires_at <= now)
    {
        let date = chrono::DateTime::from_timestamp(expires_at, 0).unwrap_or_default();
        return Err(CryptoError::Encrypt(format!(
            "key {fingerprint} expired on {date}"
        )));
    }
    let flags_encryption = |signature: &Signature| {
        let flags = signature.key_flags();
        flags.encrypt_comms() || flags.encrypt_storage()
    };
    let valid_subkey = key
        .public_subkeys
        .iter()
        .filter(|subkey| {
            let revoked = subkey
                .signatures
                .iter()
                .any(|signature| signature.typ() == Some(SignatureType::SubkeyRevocation));
            let binding = subkey
                .signatures
                .iter()
                .filter(|signature| signature.typ() == Some(SignatureType::SubkeyBinding))
                .max_by_key(|signature| signature.created().map(pgp::types::Timestamp::as_secs));
            let subkey_created = i64::from(subkey.key.created_at().as_secs());
            let valid_binding = binding.is_some_and(|binding| {
                flags_encryption(binding)
                    && binding
                        .key_expiration_time()
                        .is_none_or(|validity| subkey_created + i64::from(validity.as_secs()) > now)
            });
            subkey.key.algorithm().can_encrypt() && !revoked && valid_binding
        })
        .max_by_key(|subkey| subkey.key.created_at().as_secs());
    if let Some(subkey) = valid_subkey {
        return Ok(EncryptionKey::Subkey(&subkey.key));
    }
    // A key without key flags (older keys) may encrypt with whatever its algorithm allows.
    let without_flags = self_signatures.iter().all(|signature| {
        signature.config().is_none_or(|config| {
            !config
                .hashed_subpackets
                .iter()
                .any(|subpacket| matches!(subpacket.data, SubpacketData::KeyFlags(_)))
        })
    });
    if key.primary_key.algorithm().can_encrypt()
        && (without_flags
            || self_signatures
                .iter()
                .any(|signature| flags_encryption(signature)))
    {
        return Ok(EncryptionKey::Primary(&key.primary_key));
    }
    Err(CryptoError::Encrypt(format!(
        "key {fingerprint} has no valid encryption key"
    )))
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    const SERVER_PRIVATE: &str = include_str!("../../tests/fixtures/keys/server_private.asc");
    const SERVER_PUBLIC: &str = include_str!("../../tests/fixtures/keys/server_public.asc");
    const METADATA_PRIVATE: &str = include_str!("../../tests/fixtures/keys/metadata_private.asc");
    const METADATA_PUBLIC: &str = include_str!("../../tests/fixtures/keys/metadata_public.asc");

    /// Fixture keypair without passphrase.
    const ERIN_PUBLIC: &str = include_str!("../../tests/fixtures/keys/erin_public.asc");
    const ERIN_PRIVATE: &str = include_str!("../../tests/fixtures/keys/erin_private.asc");
    /// Erin's key asking for SEIPD v2: see `tests/fixtures/keys/README.md`.
    const ERIN_SEIPD_V2_PUBLIC: &str =
        include_str!("../../tests/fixtures/keys/erin_seipd_v2_public.asc");
    /// Written by OpenPGP.js: see `tests/fixtures/messages/README.md`.
    const SEIPD_V2_MESSAGE: &str = include_str!("../../tests/fixtures/messages/erin_seipd_v2.asc");
    const GNUPG_AEAD_MESSAGE: &str =
        include_str!("../../tests/fixtures/messages/erin_gnupg_aead.asc");
    /// Passbolt server test keys: see `tests/fixtures/keys/README.md`.
    const EXPIRED_PUBLIC: &str = include_str!("../../tests/fixtures/keys/expired_public.asc");
    const EXPIRED_PRIMARY_PUBLIC: &str =
        include_str!("../../tests/fixtures/keys/expired_primary_public.asc");
    const REVOKED_PUBLIC: &str = include_str!("../../tests/fixtures/keys/revoked_public.asc");
    const REVOKED_SUBKEY_PUBLIC: &str =
        include_str!("../../tests/fixtures/keys/revoked_subkey_public.asc");

    fn at(date: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(date).unwrap().to_utc()
    }

    fn refusal(public: &str, now: &chrono::DateTime<chrono::Utc>) -> String {
        let key = parse_public_key(public).unwrap();
        match encryption_key(&key, now) {
            Ok(_) => panic!("the key is accepted"),
            Err(error) => error.to_string(),
        }
    }

    #[rstest]
    #[case::revoked(REVOKED_PUBLIC, "is revoked")]
    #[case::expired(EXPIRED_PUBLIC, "expired on 2018-05-02")]
    #[case::expired_primary_with_a_valid_subkey(EXPIRED_PRIMARY_PUBLIC, "expired on 2024-08-22")]
    #[case::only_subkey_revoked(REVOKED_SUBKEY_PUBLIC, "no valid encryption key")]
    fn test_unusable_recipient_keys_are_refused(#[case] public: &str, #[case] reason: &str) {
        let refusal = refusal(public, &chrono::Utc::now());

        assert!(refusal.contains(reason), "{refusal}");
    }

    #[test]
    fn test_a_key_is_refused_from_its_expiry_on() {
        let key = parse_public_key(EXPIRED_PUBLIC).unwrap();

        assert!(encryption_key(&key, &at("2018-05-02T04:59:34Z")).is_ok());
        assert!(encryption_key(&key, &at("2018-05-02T04:59:35Z")).is_err());
    }

    #[test]
    fn test_a_message_for_a_revoked_key_is_not_written() {
        let revoked = parse_public_key(REVOKED_PUBLIC).unwrap();
        let (_, server_public) = keypair(SERVER_PRIVATE, SERVER_PUBLIC);

        let error = encrypt_message(b"secret", &[&server_public, &revoked]).unwrap_err();

        assert!(error.to_string().contains("is revoked"), "{error}");
    }

    #[rstest]
    #[case::subkey_of_an_ecc_key(ERIN_PUBLIC, true)]
    #[case::primary_flagged_for_encryption(SERVER_PUBLIC, false)]
    fn test_the_encryption_key_is_the_flagged_one(#[case] public: &str, #[case] subkey: bool) {
        let key = parse_public_key(public).unwrap();

        let chosen = encryption_key(&key, &chrono::Utc::now()).ok().unwrap();

        assert_eq!(matches!(chosen, EncryptionKey::Subkey(_)), subkey);
    }

    fn keypair(private: &str, public: &str) -> (SignedSecretKey, SignedPublicKey) {
        (
            parse_private_key(private).unwrap(),
            parse_public_key(public).unwrap(),
        )
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (secret, public) = keypair(SERVER_PRIVATE, SERVER_PUBLIC);

        let armored = encrypt_message(b"secret", &[&public]).unwrap();

        assert_eq!(decrypt_message(&armored, &secret, "").unwrap(), b"secret");
    }

    #[test]
    fn test_encrypt_for_multiple_keys() {
        let (server_secret, server_public) = keypair(SERVER_PRIVATE, SERVER_PUBLIC);
        let (metadata_secret, metadata_public) = keypair(METADATA_PRIVATE, METADATA_PUBLIC);

        let armored = encrypt_message(b"both", &[&server_public, &metadata_public]).unwrap();

        assert_eq!(
            decrypt_message(&armored, &server_secret, "").unwrap(),
            b"both"
        );
        assert_eq!(
            decrypt_message(&armored, &metadata_secret, "").unwrap(),
            b"both"
        );
    }

    #[test]
    fn test_decrypt_compressed_message() {
        use pgp::types::CompressionAlgorithm;
        let (secret, public) = keypair(SERVER_PRIVATE, SERVER_PUBLIC);
        let mut rng = rand::thread_rng();
        let mut builder = MessageBuilder::from_bytes("", &b"gpgauthv1.3.0"[..])
            .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
        builder.compression(CompressionAlgorithm::ZLIB);
        builder.encrypt_to_key(&mut rng, &public).unwrap();
        let armored = builder
            .to_armored_string(&mut rng, ArmorOptions::default())
            .unwrap();

        assert_eq!(
            decrypt_message(&armored, &secret, "").unwrap(),
            b"gpgauthv1.3.0"
        );
    }

    #[test]
    fn test_decrypt_with_another_key_fails() {
        let (_, server_public) = keypair(SERVER_PRIVATE, SERVER_PUBLIC);
        let (metadata_secret, _) = keypair(METADATA_PRIVATE, METADATA_PUBLIC);

        let armored = encrypt_message(b"secret", &[&server_public]).unwrap();

        assert!(decrypt_message(&armored, &metadata_secret, "").is_err());
    }

    /// Decrypt `armored`, checking it is a text literal signed by exactly `signers`, over the
    /// literal data as other `OpenPGP` implementations check them.
    fn verified_text(
        armored: &str,
        secret: &SignedSecretKey,
        signers: &[&SignedPublicKey],
    ) -> String {
        use pgp::composed::VerificationResult;
        use pgp::types::VerifyingKey;

        let mut message = parse_message(armored)
            .unwrap()
            .decrypt(&Password::empty(), secret)
            .unwrap();
        let Message::Signed { reader, .. } = &message else {
            panic!("not signed")
        };
        assert_eq!(reader.num_signatures(), signers.len(), "signature count");
        let text = message.as_data_string().unwrap();
        assert!(
            matches!(
                message
                    .literal_data_header()
                    .map(pgp::packet::LiteralDataHeader::mode),
                Some(DataMode::Utf8)
            ),
            "not a text literal"
        );
        let verifying: Vec<&dyn VerifyingKey> = signers
            .iter()
            .map(|signer| &signer.primary_key as &dyn VerifyingKey)
            .collect();
        for (result, signer) in message
            .verify_nested(&verifying)
            .unwrap()
            .iter()
            .zip(signers)
        {
            assert!(
                matches!(result, VerificationResult::Valid(_)),
                "not signed by {}",
                hex::encode_upper(signer.fingerprint().as_bytes())
            );
        }
        text.replace("\r\n", "\n")
    }

    #[test]
    fn test_sign_and_encrypt_signs_with_every_signer() {
        let (server_secret, server_public) = keypair(SERVER_PRIVATE, SERVER_PUBLIC);
        let (metadata_secret, metadata_public) = keypair(METADATA_PRIVATE, METADATA_PUBLIC);
        let signers = [
            SigningKey {
                key: &server_secret,
                passphrase: "",
            },
            SigningKey {
                key: &metadata_secret,
                passphrase: "",
            },
        ];

        let armored = sign_and_encrypt("signed é", &signers, &[&metadata_public]).unwrap();

        assert_eq!(
            verified_text(
                &armored,
                &metadata_secret,
                &[&metadata_public, &server_public]
            ),
            "signed é"
        );
    }

    #[test]
    fn test_a_kept_session_key_decrypts_the_message_again() {
        let (secret, public) = keypair(SERVER_PRIVATE, SERVER_PUBLIC);
        let armored = encrypt_message(b"metadata", &[&public]).unwrap();

        let (plaintext, session_key) =
            decrypt_message_keeping_session_key(&armored, &secret, "").unwrap();
        let stored = SessionKey::parse(&session_key.to_passbolt_string()).unwrap();

        assert_eq!(plaintext, b"metadata");
        assert_eq!(
            decrypt_with_session_key(&armored, &stored).unwrap(),
            b"metadata"
        );
        assert!(session_key.to_passbolt_string().starts_with("9:"));
    }

    #[test]
    fn test_a_session_key_of_another_message_fails() {
        let (secret, public) = keypair(SERVER_PRIVATE, SERVER_PUBLIC);
        let first = encrypt_message(b"first", &[&public]).unwrap();
        let second = encrypt_message(b"second", &[&public]).unwrap();
        let (_, session_key) = decrypt_message_keeping_session_key(&first, &secret, "").unwrap();

        assert!(decrypt_with_session_key(&second, &session_key).is_err());
    }

    #[rstest]
    #[case::seipd_v2(SEIPD_V2_MESSAGE)]
    #[case::gnupg_aead(GNUPG_AEAD_MESSAGE)]
    fn test_aead_messages_are_decrypted(#[case] armored: &str) {
        let erin = parse_private_key(ERIN_PRIVATE).unwrap();

        let plaintext = decrypt_message(armored, &erin, "erin-passphrase").unwrap();

        assert_eq!(plaintext, b"line one\nline two");
    }

    #[rstest]
    #[case::seipd_v2(SEIPD_V2_MESSAGE, "9:")]
    #[case::gnupg_aead(GNUPG_AEAD_MESSAGE, "7:")]
    fn test_the_session_key_of_an_aead_message_decrypts_it_again(
        #[case] armored: &str,
        #[case] algorithm: &str,
    ) {
        let erin = parse_private_key(ERIN_PRIVATE).unwrap();

        let (_, session_key) =
            decrypt_message_keeping_session_key(armored, &erin, "erin-passphrase").unwrap();
        let stored = SessionKey::parse(&session_key.to_passbolt_string()).unwrap();

        assert!(
            session_key.to_passbolt_string().starts_with(algorithm),
            "{}",
            session_key.to_passbolt_string()
        );
        assert_eq!(
            decrypt_with_session_key(armored, &stored).unwrap(),
            b"line one\nline two"
        );
    }

    /// The SEIPD v2 cipher suite `armored` is written with, `None` for SEIPD v1.
    fn cipher_suite_of(armored: &str) -> Option<(SymmetricKeyAlgorithm, AeadAlgorithm)> {
        let message = parse_message(armored).unwrap();
        let Message::Encrypted {
            edata: Edata::SymEncryptedProtectedData { reader },
            ..
        } = &message
        else {
            panic!("not a SEIPD message");
        };
        match reader.config() {
            ProtectedDataConfig::Seipd(SymEncryptedProtectedDataConfig::V2 {
                sym_alg,
                aead,
                ..
            }) => Some((*sym_alg, *aead)),
            _ => None,
        }
    }

    #[rstest]
    #[case::asking_for_seipd_v2(&[ERIN_SEIPD_V2_PUBLIC], Some((SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Gcm)))]
    #[case::not_asking(&[ERIN_PUBLIC], None)]
    #[case::not_all_asking(&[ERIN_SEIPD_V2_PUBLIC, SERVER_PUBLIC], None)]
    fn test_seipd_v2_is_written_when_every_recipient_asks_for_it(
        #[case] recipients: &[&str],
        #[case] cipher_suite: Option<(SymmetricKeyAlgorithm, AeadAlgorithm)>,
    ) {
        let keys: Vec<SignedPublicKey> = recipients
            .iter()
            .map(|public| parse_public_key(public).unwrap())
            .collect();

        let armored = encrypt_message(b"secret", &keys.iter().collect::<Vec<_>>()).unwrap();

        assert_eq!(cipher_suite_of(&armored), cipher_suite);
    }

    #[test]
    fn test_a_seipd_v2_message_is_decrypted_with_its_session_key() {
        let erin = parse_private_key(ERIN_PRIVATE).unwrap();
        let recipient = parse_public_key(ERIN_SEIPD_V2_PUBLIC).unwrap();
        let armored = encrypt_message(b"secret", &[&recipient]).unwrap();

        let (plaintext, session_key) =
            decrypt_message_keeping_session_key(&armored, &erin, "erin-passphrase").unwrap();

        assert_eq!(plaintext, b"secret");
        assert_eq!(
            decrypt_with_session_key(&armored, &session_key).unwrap(),
            b"secret"
        );
    }
}
