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

use pgp::composed::{
    ArmorOptions, Deserializable, Message, MessageBuilder, PlainSessionKey, RawSessionKey,
    SignedPublicKey, SignedSecretKey,
};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::DataMode;
use pgp::types::{DecryptionKey, EskType, KeyDetails, Password, PkeskVersion};
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
    let (key, _) = SignedSecretKey::from_armor_single(armored.as_bytes())
        .map_err(|error| CryptoError::KeyParse(format!("private key: {error}")))?;
    key.verify_bindings()
        .map_err(|error| CryptoError::KeyParse(format!("private key verification: {error}")))?;

    let fingerprint = hex::encode_upper(key.fingerprint().as_bytes());
    Ok(PrivateKey { key, fingerprint })
}

/// Parse a PGP public key from ASCII-armored text.
pub fn parse_public_key(armored: &str) -> Result<SignedPublicKey, CryptoError> {
    let (key, _) = SignedPublicKey::from_armor_single(armored.as_bytes())
        .map_err(|error| CryptoError::KeyParse(format!("public key: {error}")))?;
    key.verify_bindings()
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
    let message = parse_message(armored_message)?;
    let decrypted = message
        .decrypt(&Password::from(passphrase), private_key)
        .map_err(|error| CryptoError::Decrypt(format!("{error}")))?;
    content(decrypted)
}

/// The symmetric key of one message, as Passbolt stores it: `<algorithm id>:<hex key>`.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionKey {
    algorithm: SymmetricKeyAlgorithm,
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

    fn plain(&self) -> PlainSessionKey {
        PlainSessionKey::V3_4 {
            sym_alg: self.algorithm,
            key: RawSessionKey::from(self.key.to_vec()),
        }
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
    let failure = |reason: String| CryptoError::Decrypt(reason);
    let message = parse_message(armored_message)?;
    let Message::Encrypted { esk, .. } = &message else {
        return Err(failure("not an encrypted message".into()));
    };
    let password = Password::from(passphrase);
    let decrypt_with = |key: &dyn DecryptionKey,
                        pkesk: &pgp::packet::PublicKeyEncryptedSessionKey| {
        let values = pkesk.values().ok()?;
        key.decrypt(&password, values, EskType::V3_4).ok()?.ok()
    };
    let plain_key = esk
        .iter()
        .filter_map(|esk| match esk {
            pgp::composed::Esk::PublicKeyEncryptedSessionKey(pkesk)
                if pkesk.version() == PkeskVersion::V3 =>
            {
                Some(pkesk)
            }
            _ => None,
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
    let PlainSessionKey::V3_4 { sym_alg, key } = &plain_key else {
        return Err(failure("unsupported session key version".into()));
    };
    let session_key = SessionKey {
        algorithm: *sym_alg,
        key: zeroize::Zeroizing::new(key.as_ref().to_vec()),
    };
    let decrypted = message
        .decrypt_with_session_key(plain_key)
        .map_err(|error| failure(error.to_string()))?;
    Ok((content(decrypted)?, session_key))
}

/// Decrypt with the session key of the message.
pub fn decrypt_with_session_key(
    armored_message: &str,
    session_key: &SessionKey,
) -> Result<Vec<u8>, CryptoError> {
    let decrypted = parse_message(armored_message)?
        .decrypt_with_session_key(session_key.plain())
        .map_err(|error| CryptoError::Decrypt(error.to_string()))?;
    content(decrypted)
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

/// Encrypt `plaintext` for `recipients`, as a binary literal.
pub fn encrypt_message(
    plaintext: &[u8],
    recipients: &[&SignedPublicKey],
) -> Result<String, CryptoError> {
    encrypt(plaintext.to_vec(), DataMode::Binary, &[], recipients)
}

/// A key able to sign: a private key and its passphrase.
pub struct Signer<'a> {
    pub key: &'a SignedSecretKey,
    pub passphrase: &'a str,
}

/// Sign `plaintext` with every signer, then encrypt it for `recipients`, as a UTF-8 text literal.
///
/// Passbolt clients sign secrets with the user key, shared metadata with the metadata key too.
/// Every signature covers the literal data, as `OpenPGP.js` and gopenpgp write and check them.
pub fn sign_and_encrypt(
    plaintext: &str,
    signers: &[Signer<'_>],
    recipients: &[&SignedPublicKey],
) -> Result<String, CryptoError> {
    // UTF-8 literals are written with CR LF line endings.
    let text = plaintext.replace("\r\n", "\n").replace('\n', "\r\n");
    encrypt(text.into_bytes(), DataMode::Utf8, signers, recipients)
}

fn encrypt(
    data: Vec<u8>,
    mode: DataMode,
    signers: &[Signer<'_>],
    recipients: &[&SignedPublicKey],
) -> Result<String, CryptoError> {
    let failure = |error: pgp::errors::Error| CryptoError::Encrypt(error.to_string());
    let mut rng = rand::thread_rng();
    let mut builder =
        MessageBuilder::from_bytes("", data).seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
    builder.data_mode(mode).map_err(failure)?;
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
    // Recipients mix primary keys and subkeys: one session key packet each.
    let now = chrono::Utc::now();
    for recipient in recipients {
        match encryption_key(recipient, &now)? {
            EncryptionKey::Subkey(subkey) => builder.encrypt_to_key(&mut rng, subkey),
            EncryptionKey::Primary(primary_key) => builder.encrypt_to_key(&mut rng, primary_key),
        }
        .map_err(failure)?;
    }
    builder
        .to_armored_string(&mut rng, ArmorOptions::default())
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
