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

//! `OpenPGP` operations, run by the engine a key was read with: rpgp unless another is chosen.

#[cfg(all(feature = "openpgpjs", not(target_arch = "wasm32")))]
mod openpgpjs;
mod rpgp;

use std::any::Any;
use std::sync::Arc;

use zeroize::{Zeroize, Zeroizing};

#[cfg(all(feature = "openpgpjs", not(target_arch = "wasm32")))]
pub use self::openpgpjs::OpenPgpJs;
pub use self::rpgp::Rpgp;
use crate::error::CryptoError;

/// What an engine keeps of a key it read.
pub type KeyHandle = Arc<dyn Any + Send + Sync>;

/// An `OpenPGP` implementation, writing and reading messages as the browser extension does.
///
/// Decrypted text literals come back with LF line endings, binary literals as they are.
/// Messages are written for the newest valid encryption subkey of each recipient (else its
/// primary key), as SEIPD v2 only when every recipient asks for it; revoked and expired keys
/// are refused.
pub trait Engine: Send + Sync {
    /// The name the engine is chosen by.
    fn name(&self) -> &'static str;

    /// Read and check an armored private key; its fingerprint in upper-case hexadecimal.
    fn parse_private_key(&self, armored: &str) -> Result<(KeyHandle, String), CryptoError>;

    /// Read and check an armored public key; its fingerprint in upper-case hexadecimal.
    fn parse_public_key(&self, armored: &str) -> Result<(KeyHandle, String), CryptoError>;

    fn decrypt(
        &self,
        armored_message: &str,
        private_key: &KeyHandle,
        passphrase: &str,
    ) -> Result<Vec<u8>, CryptoError>;

    /// Decrypt, giving the session key of the message too.
    fn decrypt_keeping_session_key(
        &self,
        armored_message: &str,
        private_key: &KeyHandle,
        passphrase: &str,
    ) -> Result<(Vec<u8>, SessionKey), CryptoError>;

    fn decrypt_with_session_key(
        &self,
        armored_message: &str,
        session_key: &SessionKey,
    ) -> Result<Vec<u8>, CryptoError>;

    /// Encrypt `plaintext` for `recipients`, as a binary literal.
    fn encrypt(&self, plaintext: &[u8], recipients: &[&KeyHandle]) -> Result<String, CryptoError>;

    /// Sign `plaintext` with every `(private key, passphrase)`, then encrypt it for `recipients`,
    /// as a UTF-8 text literal; every signature covers the literal data.
    fn sign_and_encrypt(
        &self,
        plaintext: &str,
        signers: &[(&KeyHandle, &str)],
        recipients: &[&KeyHandle],
    ) -> Result<String, CryptoError>;
}

/// The key an engine read, `Err` for a key another engine read.
pub fn key_of<T: Any>(handle: &KeyHandle) -> Result<&T, CryptoError> {
    handle
        .downcast_ref::<T>()
        .ok_or_else(|| CryptoError::KeyParse("a key read by another OpenPGP engine".into()))
}

/// The engine keys are read with, and through them every message operation.
#[derive(Clone)]
pub struct OpenPgp(Arc<dyn Engine>);

impl OpenPgp {
    #[must_use]
    pub fn new(engine: impl Engine + 'static) -> Self {
        Self(Arc::new(engine))
    }

    #[must_use]
    pub fn rpgp() -> Self {
        Self::new(Rpgp)
    }

    /// The OpenPGP.js engine, the library of the browser extension, in a JavaScript runtime
    /// of its own.
    #[cfg(all(feature = "openpgpjs", not(target_arch = "wasm32")))]
    pub fn openpgpjs() -> Result<Self, CryptoError> {
        Ok(Self::new(OpenPgpJs::new()?))
    }

    #[must_use]
    pub fn name(&self) -> &'static str {
        self.0.name()
    }

    pub fn parse_private_key(&self, armored: &str) -> Result<PrivateKey, CryptoError> {
        let (handle, fingerprint) = self.0.parse_private_key(armored)?;
        Ok(PrivateKey {
            openpgp: self.clone(),
            handle,
            fingerprint,
        })
    }

    pub fn parse_public_key(&self, armored: &str) -> Result<PublicKey, CryptoError> {
        let (handle, fingerprint) = self.0.parse_public_key(armored)?;
        Ok(PublicKey {
            openpgp: self.clone(),
            handle,
            fingerprint,
        })
    }

    /// The fingerprint of an armored public key, in upper-case hexadecimal as Passbolt shows it.
    pub fn public_key_fingerprint(&self, armored: &str) -> Result<String, CryptoError> {
        Ok(self.parse_public_key(armored)?.fingerprint)
    }

    pub fn decrypt_with_session_key(
        &self,
        armored_message: &str,
        session_key: &SessionKey,
    ) -> Result<Vec<u8>, CryptoError> {
        self.0
            .decrypt_with_session_key(armored_message, session_key)
    }
}

impl Default for OpenPgp {
    fn default() -> Self {
        Self::rpgp()
    }
}

impl std::fmt::Debug for OpenPgp {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.name())
    }
}

/// A private key and the engine that read it.
#[derive(Clone)]
pub struct PrivateKey {
    openpgp: OpenPgp,
    handle: KeyHandle,
    pub fingerprint: String,
}

impl PrivateKey {
    #[must_use]
    pub const fn openpgp(&self) -> &OpenPgp {
        &self.openpgp
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.fingerprint.zeroize();
    }
}

/// A public key and the engine that read it.
#[derive(Clone)]
pub struct PublicKey {
    openpgp: OpenPgp,
    handle: KeyHandle,
    pub fingerprint: String,
}

/// Parse and validate a private key with the default engine.
pub fn parse_private_key(armored: &str) -> Result<PrivateKey, CryptoError> {
    OpenPgp::default().parse_private_key(armored)
}

/// Parse and validate a public key with the default engine.
pub fn parse_public_key(armored: &str) -> Result<PublicKey, CryptoError> {
    OpenPgp::default().parse_public_key(armored)
}

/// The fingerprint of an armored public key, read with the default engine.
pub fn public_key_fingerprint(armored: &str) -> Result<String, CryptoError> {
    OpenPgp::default().public_key_fingerprint(armored)
}

pub fn decrypt_message(
    armored_message: &str,
    private_key: &PrivateKey,
    passphrase: &str,
) -> Result<Vec<u8>, CryptoError> {
    private_key
        .openpgp
        .0
        .decrypt(armored_message, &private_key.handle, passphrase)
}

/// Decrypt with `private_key`, and give the session key of the message, to decrypt it again
/// without the costly public key operation.
pub fn decrypt_message_keeping_session_key(
    armored_message: &str,
    private_key: &PrivateKey,
    passphrase: &str,
) -> Result<(Vec<u8>, SessionKey), CryptoError> {
    private_key.openpgp.0.decrypt_keeping_session_key(
        armored_message,
        &private_key.handle,
        passphrase,
    )
}

/// The engine of `recipients`, which all keys of a message must share.
fn engine_of<'a>(recipients: &[&'a PublicKey]) -> Result<&'a OpenPgp, CryptoError> {
    recipients
        .first()
        .map(|recipient| &recipient.openpgp)
        .ok_or_else(|| CryptoError::Encrypt("no recipient".into()))
}

/// Encrypt `plaintext` for `recipients`, as a binary literal.
pub fn encrypt_message(plaintext: &[u8], recipients: &[&PublicKey]) -> Result<String, CryptoError> {
    let handles: Vec<&KeyHandle> = recipients.iter().map(|key| &key.handle).collect();
    engine_of(recipients)?.0.encrypt(plaintext, &handles)
}

/// A key able to sign: a private key and its passphrase.
pub struct Signer<'a> {
    pub key: &'a PrivateKey,
    pub passphrase: &'a str,
}

/// Sign `plaintext` with every signer, then encrypt it for `recipients`, as a UTF-8 text literal.
///
/// Passbolt clients sign secrets with the user key, shared metadata with the metadata key too.
/// Every signature covers the literal data, as `OpenPGP.js` and gopenpgp write and check them.
pub fn sign_and_encrypt(
    plaintext: &str,
    signers: &[Signer<'_>],
    recipients: &[&PublicKey],
) -> Result<String, CryptoError> {
    let signers: Vec<(&KeyHandle, &str)> = signers
        .iter()
        .map(|signer| (&signer.key.handle, signer.passphrase))
        .collect();
    let handles: Vec<&KeyHandle> = recipients.iter().map(|key| &key.handle).collect();
    engine_of(recipients)?
        .0
        .sign_and_encrypt(plaintext, &signers, &handles)
}

/// The symmetric key of one message, as Passbolt stores it: `<algorithm id>:<hex key>`.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionKey {
    algorithm: u8,
    key: Zeroizing<Vec<u8>>,
}

impl SessionKey {
    /// A key of the symmetric algorithm `algorithm`, by its `OpenPGP` id.
    #[must_use]
    pub fn new(algorithm: u8, key: Vec<u8>) -> Self {
        Self {
            algorithm,
            key: Zeroizing::new(key),
        }
    }

    /// Read `9:HEX`; a key without algorithm is AES-256, as Passbolt clients write it.
    pub fn parse(text: &str) -> Result<Self, CryptoError> {
        let (algorithm, key) = text.split_once(':').unwrap_or(("9", text));
        let invalid = || CryptoError::Decrypt("invalid session key".into());
        let algorithm = algorithm.parse::<u8>().map_err(|_| invalid())?;
        let key = hex::decode(key).map_err(|_| invalid())?;
        Ok(Self::new(algorithm, key))
    }

    /// `<algorithm id>:<HEX>`, the format of Passbolt session key bundles.
    #[must_use]
    pub fn to_passbolt_string(&self) -> String {
        format!(
            "{}:{}",
            self.algorithm,
            hex::encode_upper(self.key.as_slice())
        )
    }

    /// The `OpenPGP` id of its symmetric algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> u8 {
        self.algorithm
    }

    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key
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

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    const SERVER_PRIVATE: &str = include_str!("../../tests/fixtures/keys/server_private.asc");
    const SERVER_PUBLIC: &str = include_str!("../../tests/fixtures/keys/server_public.asc");

    #[test]
    fn test_parse_private_key_invalid() {
        assert!(parse_private_key("not a pgp key at all").is_err());
    }

    #[test]
    fn test_parse_public_key_invalid() {
        assert!(parse_public_key("garbage data").is_err());
    }

    #[test]
    fn test_a_fingerprint_is_upper_case_hexadecimal() {
        let fingerprint = parse_private_key(SERVER_PRIVATE)
            .unwrap()
            .fingerprint
            .clone();

        assert_eq!(fingerprint.len(), 40);
        assert!(fingerprint
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_lowercase()));
        assert_eq!(public_key_fingerprint(SERVER_PUBLIC).unwrap(), fingerprint);
    }

    #[test]
    fn test_a_message_needs_a_recipient() {
        assert!(encrypt_message(b"secret", &[]).is_err());
    }

    #[test]
    fn test_the_default_engine_is_rpgp() {
        assert_eq!(OpenPgp::default().name(), "rpgp");
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
