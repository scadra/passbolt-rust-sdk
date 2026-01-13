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
            let packet = match encryption_subkey(recipient) {
                Some(subkey) => PublicKeyEncryptedSessionKey::from_session_key_v3(
                    &mut rng,
                    &session_key,
                    ALGORITHM,
                    &subkey.key,
                ),
                None if recipient.primary_key.is_encryption_key() => {
                    PublicKeyEncryptedSessionKey::from_session_key_v3(
                        &mut rng,
                        &session_key,
                        ALGORITHM,
                        &recipient.primary_key,
                    )
                }
                None => {
                    return Err(CryptoError::Encrypt(format!(
                        "key {} has no encryption key",
                        hex::encode_upper(recipient.fingerprint().as_bytes())
                    )))
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

/// The subkey flagged for encryption, as `OpenPGP` requires over the primary key.
fn encryption_subkey(key: &SignedPublicKey) -> Option<&pgp::SignedPublicSubKey> {
    key.public_subkeys.iter().find(|subkey| {
        subkey.key.is_encryption_key()
            && subkey.signatures.iter().any(|signature| {
                let flags = signature.key_flags();
                flags.encrypt_comms() || flags.encrypt_storage()
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER_PRIVATE: &str = include_str!("../tests/fixtures/keys/server_private.asc");
    const SERVER_PUBLIC: &str = include_str!("../tests/fixtures/keys/server_public.asc");
    const METADATA_PRIVATE: &str = include_str!("../tests/fixtures/keys/metadata_private.asc");
    const METADATA_PUBLIC: &str = include_str!("../tests/fixtures/keys/metadata_public.asc");

    /// Fixture keypair without passphrase.
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

    #[rstest::rstest]
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
