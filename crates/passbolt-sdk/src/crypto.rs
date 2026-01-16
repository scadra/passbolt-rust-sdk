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

use pgp::{
    ser::Serialize, types::PublicKeyTrait, ArmorOptions, Deserializable, Message, SignedPublicKey,
    SignedSecretKey,
};
use std::io::Cursor;
use zeroize::Zeroize;

use crate::error::CryptoError;

/// Parsed private key used for decryption / fingerprint.
pub struct PrivateKey {
    pub key: SignedSecretKey,
    pub fingerprint: String,
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.fingerprint.zeroize();
    }
}

/// Parse and validate a PGP private key from ASCII-armored text.
pub fn parse_private_key(armored: &str) -> Result<PrivateKey, CryptoError> {
    let cursor = Cursor::new(armored.as_bytes());
    let (key, _) = SignedSecretKey::from_armor_single(cursor)
        .map_err(|error| CryptoError::KeyParse(format!("private key: {error}")))?;
    key.verify()
        .map_err(|error| CryptoError::KeyParse(format!("private key verification: {error}")))?;

    let fingerprint = hex::encode(key.fingerprint().as_bytes()).to_uppercase();
    Ok(PrivateKey { key, fingerprint })
}

/// Parse a PGP public key from ASCII-armored text.
pub fn parse_public_key(armored: &str) -> Result<SignedPublicKey, CryptoError> {
    let cursor = Cursor::new(armored.as_bytes());
    let (key, _) = SignedPublicKey::from_armor_single(cursor)
        .map_err(|error| CryptoError::KeyParse(format!("public key: {error}")))?;
    key.verify()
        .map_err(|error| CryptoError::KeyParse(format!("public key verification: {error}")))?;
    Ok(key)
}

/// The fingerprint of an armored public key, in upper-case hexadecimal as Passbolt shows it.
pub fn public_key_fingerprint(armored: &str) -> Result<String, CryptoError> {
    let key = parse_public_key(armored)?;
    Ok(hex::encode_upper(key.fingerprint().as_bytes()))
}

pub fn decrypt_message(
    armored_message: &str,
    private_key: &SignedSecretKey,
    passphrase: &str,
) -> Result<Vec<u8>, CryptoError> {
    let cursor = Cursor::new(armored_message.as_bytes());
    let (message, _) = Message::from_armor_single(cursor)
        .map_err(|error| CryptoError::Decrypt(format!("parse message: {error}")))?;

    let (decrypted, _) = message
        .decrypt(|| passphrase.to_string(), &[private_key])
        .map_err(|error| CryptoError::Decrypt(format!("{error}")))?;

    // GnuPG (the Passbolt server) compresses by default.
    content(&decrypted)
}

/// The symmetric key of one message, as Passbolt stores it: `<algorithm id>:<hex key>`.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionKey {
    algorithm: pgp::crypto::sym::SymmetricKeyAlgorithm,
    key: zeroize::Zeroizing<Vec<u8>>,
}

impl SessionKey {
    /// Read `9:HEX`; a key without algorithm is AES-256, as Passbolt clients write it.
    pub fn parse(text: &str) -> Result<Self, CryptoError> {
        let (algorithm, key) = text.split_once(':').unwrap_or(("9", text));
        let invalid = || CryptoError::Decrypt("invalid session key".into());
        let algorithm = algorithm.parse::<u8>().map_err(|_| invalid())?;
        let key = hex::decode(key).map_err(|_| invalid())?;
        Ok(Self {
            algorithm: algorithm.into(),
            key: zeroize::Zeroizing::new(key),
        })
    }

    /// `<algorithm id>:<HEX>`, the format of Passbolt session key bundles.
    #[must_use]
    pub fn to_passbolt_string(&self) -> String {
        format!(
            "{}:{}",
            u8::from(self.algorithm),
            hex::encode_upper(self.key.as_slice())
        )
    }
}

/// Never print the key itself.
impl std::fmt::Debug for SessionKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionKey")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// Decrypt with `private_key`, and give the session key of the message, to decrypt it again
/// without the costly public key operation.
pub fn decrypt_message_keeping_session_key(
    armored_message: &str,
    private_key: &SignedSecretKey,
    passphrase: &str,
) -> Result<(Vec<u8>, SessionKey), CryptoError> {
    use pgp::composed::{decrypt_session_key, PlainSessionKey};
    use pgp::types::{EskType, PkeskVersion};

    let failure = |reason: String| CryptoError::Decrypt(reason);
    let (message, _) = Message::from_armor_single(Cursor::new(armored_message.as_bytes()))
        .map_err(|error| failure(format!("parse message: {error}")))?;
    let Message::Encrypted { esk, edata } = message else {
        return Err(failure("not an encrypted message".into()));
    };
    let passphrase = || passphrase.to_string();
    let plain_key = esk
        .iter()
        .filter_map(|esk| match esk {
            pgp::Esk::PublicKeyEncryptedSessionKey(pkesk)
                if pkesk.version() == PkeskVersion::V3 =>
            {
                Some(pkesk)
            }
            _ => None,
        })
        .find_map(|pkesk| {
            let values = pkesk.values().ok()?;
            if pkesk.match_identity(&private_key.primary_key) {
                return decrypt_session_key(
                    &private_key.primary_key,
                    passphrase,
                    values,
                    EskType::V3_4,
                )
                .ok();
            }
            let subkey = private_key
                .secret_subkeys
                .iter()
                .find(|subkey| pkesk.match_identity(&subkey.key))?;
            decrypt_session_key(&subkey.key, passphrase, values, EskType::V3_4).ok()
        })
        .ok_or_else(|| failure("no session key for this key".into()))?;
    let PlainSessionKey::V3_4 { sym_alg, key } = &plain_key else {
        return Err(failure("unsupported session key version".into()));
    };
    let session_key = SessionKey {
        algorithm: *sym_alg,
        key: zeroize::Zeroizing::new(key.clone()),
    };
    let decrypted = edata
        .decrypt(plain_key)
        .map_err(|error| failure(error.to_string()))?;
    Ok((content(&decrypted)?, session_key))
}

/// Decrypt with the session key of the message.
pub fn decrypt_with_session_key(
    armored_message: &str,
    session_key: &SessionKey,
) -> Result<Vec<u8>, CryptoError> {
    use pgp::composed::PlainSessionKey;

    let failure = |reason: String| CryptoError::Decrypt(reason);
    let (message, _) = Message::from_armor_single(Cursor::new(armored_message.as_bytes()))
        .map_err(|error| failure(format!("parse message: {error}")))?;
    let Message::Encrypted { edata, .. } = message else {
        return Err(failure("not an encrypted message".into()));
    };
    let decrypted = edata
        .decrypt(PlainSessionKey::V3_4 {
            sym_alg: session_key.algorithm,
            key: session_key.key.to_vec(),
        })
        .map_err(|error| failure(error.to_string()))?;
    content(&decrypted)
}

/// The literal content of a decrypted message, decompressed.
fn content(message: &Message) -> Result<Vec<u8>, CryptoError> {
    message
        .get_content()
        .map_err(|error| CryptoError::Decrypt(format!("decompress: {error}")))?
        .ok_or_else(|| CryptoError::Decrypt("no literal content".into()))
}

/// Encrypt `plaintext` for `recipients`, as a binary literal.
pub fn encrypt_message(
    plaintext: &[u8],
    recipients: &[&SignedPublicKey],
) -> Result<String, CryptoError> {
    encrypt(&Message::new_literal_bytes("", plaintext), recipients)
}

/// A key able to sign: a private key and its passphrase.
pub struct Signer<'a> {
    pub key: &'a SignedSecretKey,
    pub passphrase: &'a str,
}

/// Sign `plaintext` with every signer, then encrypt it for `recipients`, as a UTF-8 text literal.
///
/// Passbolt clients sign secrets with the user key, shared metadata with the metadata key too.
/// Every signature covers the literal data, as `OpenPGP.js` and gopenpgp write and check them:
/// one-pass signatures in a row, then the literal, then the signatures in reverse order.
pub fn sign_and_encrypt(
    plaintext: &str,
    signers: &[Signer<'_>],
    recipients: &[&SignedPublicKey],
) -> Result<String, CryptoError> {
    use pgp::crypto::hash::HashAlgorithm;

    let literal = Message::new_literal("", plaintext);
    let mut message = literal.clone();
    for (index, signer) in signers.iter().enumerate() {
        let signed = literal
            .clone()
            .sign(
                rand::thread_rng(),
                signer.key,
                || signer.passphrase.to_string(),
                HashAlgorithm::SHA2_256,
            )
            .map_err(|error| CryptoError::Encrypt(format!("sign: {error}")))?;
        let Message::Signed {
            mut one_pass_signature,
            signature,
            ..
        } = signed
        else {
            return Err(CryptoError::Encrypt("sign: no signature".into()));
        };
        // Only the one-pass signature right before the literal is the last one.
        if index > 0 {
            if let Some(one_pass_signature) = one_pass_signature.as_mut() {
                one_pass_signature.last = 0;
            }
        }
        message = Message::Signed {
            message: Some(Box::new(message)),
            one_pass_signature,
            signature,
        };
    }
    encrypt(&message, recipients)
}

fn encrypt(message: &Message, recipients: &[&SignedPublicKey]) -> Result<String, CryptoError> {
    use pgp::crypto::sym::SymmetricKeyAlgorithm;
    use pgp::packet::{PublicKeyEncryptedSessionKey, SymEncryptedProtectedData};
    use pgp::{Edata, Esk};

    const ALGORITHM: SymmetricKeyAlgorithm = SymmetricKeyAlgorithm::AES256;
    let failure = |error: pgp::errors::Error| CryptoError::Encrypt(error.to_string());
    let mut rng = rand::thread_rng();
    let session_key = ALGORITHM.new_session_key(&mut rng);

    // Recipients mix primary keys and subkeys: one session key packet each.
    let esk = recipients
        .iter()
        .map(|recipient| {
            let packet = match encryption_key(recipient, &chrono::Utc::now())? {
                EncryptionKey::Subkey(subkey) => PublicKeyEncryptedSessionKey::from_session_key_v3(
                    &mut rng,
                    &session_key,
                    ALGORITHM,
                    subkey,
                ),
                EncryptionKey::Primary(primary_key) => {
                    PublicKeyEncryptedSessionKey::from_session_key_v3(
                        &mut rng,
                        &session_key,
                        ALGORITHM,
                        primary_key,
                    )
                }
            };
            packet
                .map(Esk::PublicKeyEncryptedSessionKey)
                .map_err(failure)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let data = message.to_bytes().map_err(failure)?;
    let edata = Edata::SymEncryptedProtectedData(
        SymEncryptedProtectedData::encrypt_seipdv1(&mut rng, ALGORITHM, &session_key, &data)
            .map_err(failure)?,
    );
    Message::Encrypted { esk, edata }
        .to_armored_string(ArmorOptions::default())
        .map_err(|error| CryptoError::Encrypt(format!("armor: {error}")))
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
    use pgp::packet::SignatureType;

    let fingerprint = hex::encode_upper(key.fingerprint().as_bytes());
    if !key.details.revocation_signatures.is_empty() {
        return Err(CryptoError::Encrypt(format!(
            "key {fingerprint} is revoked"
        )));
    }
    if let Some(expires_at) = key.expires_at().filter(|expires_at| expires_at <= now) {
        return Err(CryptoError::Encrypt(format!(
            "key {fingerprint} expired on {expires_at}"
        )));
    }
    let flags_encryption = |signature: &pgp::packet::Signature| {
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
                .any(|signature| signature.typ() == SignatureType::SubkeyRevocation);
            let binding = subkey
                .signatures
                .iter()
                .filter(|signature| signature.typ() == SignatureType::SubkeyBinding)
                .max_by_key(|signature| signature.created().copied());
            let valid_binding = binding.is_some_and(|binding| {
                flags_encryption(binding)
                    && binding
                        .key_expiration_time()
                        .is_none_or(|validity| *subkey.key.created_at() + *validity > *now)
            });
            subkey.key.is_encryption_key() && !revoked && valid_binding
        })
        .max_by_key(|subkey| *subkey.key.created_at());
    if let Some(subkey) = valid_subkey {
        return Ok(EncryptionKey::Subkey(&subkey.key));
    }
    // A key without key flags (older keys) may encrypt with whatever its algorithm allows.
    let self_signatures: Vec<_> = key
        .details
        .users
        .iter()
        .flat_map(|user| &user.signatures)
        .collect();
    let without_flags = self_signatures.iter().all(|signature| {
        !signature
            .config
            .hashed_subpackets
            .iter()
            .any(|subpacket| matches!(subpacket.data, pgp::packet::SubpacketData::KeyFlags(_)))
    });
    if key.primary_key.is_encryption_key()
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

    const SERVER_PRIVATE: &str = include_str!("../tests/fixtures/keys/server_private.asc");
    const SERVER_PUBLIC: &str = include_str!("../tests/fixtures/keys/server_public.asc");
    const METADATA_PRIVATE: &str = include_str!("../tests/fixtures/keys/metadata_private.asc");
    const METADATA_PUBLIC: &str = include_str!("../tests/fixtures/keys/metadata_public.asc");

    /// Fixture keypair without passphrase.
    const ERIN_PUBLIC: &str = include_str!("../tests/fixtures/keys/erin_public.asc");
    /// Passbolt server test keys: see `tests/fixtures/keys/README.md`.
    const EXPIRED_PUBLIC: &str = include_str!("../tests/fixtures/keys/expired_public.asc");
    const EXPIRED_PRIMARY_PUBLIC: &str =
        include_str!("../tests/fixtures/keys/expired_primary_public.asc");
    const REVOKED_PUBLIC: &str = include_str!("../tests/fixtures/keys/revoked_public.asc");
    const REVOKED_SUBKEY_PUBLIC: &str =
        include_str!("../tests/fixtures/keys/revoked_subkey_public.asc");

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
            parse_private_key(private).unwrap().key.clone(),
            parse_public_key(public).unwrap(),
        )
    }

    #[test]
    fn test_parse_private_key_invalid() {
        assert!(parse_private_key("not a pgp key at all").is_err());
    }

    #[test]
    fn test_parse_private_key_fingerprint() {
        let fingerprint = parse_private_key(SERVER_PRIVATE)
            .unwrap()
            .fingerprint
            .clone();

        assert_eq!(fingerprint.len(), 40);
        assert!(fingerprint
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_lowercase()));
    }

    #[test]
    fn test_parse_public_key_invalid() {
        assert!(parse_public_key("garbage data").is_err());
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
        use pgp::crypto::sym::SymmetricKeyAlgorithm;
        use pgp::types::CompressionAlgorithm;
        let (secret, public) = keypair(SERVER_PRIVATE, SERVER_PUBLIC);
        let armored = Message::new_literal_bytes("", b"gpgauthv1.3.0")
            .compress(CompressionAlgorithm::ZLIB)
            .unwrap()
            .encrypt_to_keys_seipdv1(
                rand::thread_rng(),
                SymmetricKeyAlgorithm::AES256,
                &[&public],
            )
            .unwrap()
            .to_armored_string(ArmorOptions::default())
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

    /// Verify that every signature of `armored`, outermost first, is `signers`' over the literal
    /// data, as other `OpenPGP` implementations check them.
    fn verified_text(
        armored: &str,
        secret: &SignedSecretKey,
        signers: &[&SignedPublicKey],
    ) -> String {
        let (message, _) = Message::from_armor_single(Cursor::new(armored.as_bytes())).unwrap();
        let (mut message, _) = message.decrypt(String::new, &[secret]).unwrap();
        let mut signatures = Vec::new();
        while let Message::Signed {
            message: inner,
            signature,
            ..
        } = message
        {
            signatures.push(signature);
            message = *inner.unwrap();
        }
        let Message::Literal(literal) = message else {
            panic!("no literal data")
        };
        assert!(!literal.is_binary(), "not a text literal");
        assert_eq!(signatures.len(), signers.len(), "signature count");
        for (signature, signer) in signatures.iter().zip(signers) {
            signature
                .verify(*signer, literal.data())
                .unwrap_or_else(|error| {
                    panic!(
                        "not signed by {}: {error}",
                        hex::encode_upper(signer.fingerprint().as_bytes())
                    )
                });
        }
        literal.to_string().unwrap()
    }

    #[test]
    fn test_sign_and_encrypt_signs_with_every_signer() {
        let (server_secret, server_public) = keypair(SERVER_PRIVATE, SERVER_PUBLIC);
        let (metadata_secret, metadata_public) = keypair(METADATA_PRIVATE, METADATA_PUBLIC);
        let signers = [
            Signer {
                key: &server_secret,
                passphrase: "",
            },
            Signer {
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
    #[case::not_hex("9:zz")]
    #[case::bad_algorithm("x:00")]
    fn test_an_invalid_session_key_is_refused(#[case] text: &str) {
        assert!(SessionKey::parse(text).is_err());
    }

    #[test]
    fn test_a_session_key_without_algorithm_is_aes_256() {
        let session_key = SessionKey::parse("00FF").unwrap();

        assert_eq!(session_key.to_passbolt_string(), "9:00FF");
    }
}
