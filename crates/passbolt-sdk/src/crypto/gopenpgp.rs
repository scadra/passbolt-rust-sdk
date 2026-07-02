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

//! The gopenpgp engine, the library of go-passbolt: `gopenpgp/`, built by `build.rs` with Go
//! and linked, takes a JSON request and gives a JSON response.

use std::ffi::c_char;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{key_of, ready, CryptoFuture, Engine, KeyHandle, SessionKey};
use crate::error::CryptoError;

extern "C" {
    fn passbolt_gopenpgp_call(
        input: *const c_char,
        length: usize,
        output_length: *mut usize,
    ) -> *mut c_char;
    fn passbolt_gopenpgp_free(output: *mut c_char);
}

/// Go writes `[]byte` as base64 in JSON.
mod base64_bytes {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = Option::<String>::deserialize(deserializer)?.unwrap_or_default();
        base64::engine::general_purpose::STANDARD
            .decode(text)
            .map_err(serde::de::Error::custom)
    }

    pub fn deserialize_secret<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, D::Error> {
        deserialize(deserializer).map(zeroize::Zeroizing::new)
    }
}

#[derive(Serialize, Default)]
struct Request<'a> {
    op: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    armored: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    message: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    key: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    passphrase: &'a str,
    #[serde(with = "base64_bytes", skip_serializing_if = "<[u8]>::is_empty")]
    data: &'a [u8],
    #[serde(skip_serializing_if = "str::is_empty")]
    text: &'a str,
    algorithm: u8,
    #[serde(with = "base64_bytes", skip_serializing_if = "<[u8]>::is_empty")]
    session_key: &'a [u8],
    signers: Vec<Signer<'a>>,
    recipients: Vec<&'a str>,
}

#[derive(Serialize)]
struct Signer<'a> {
    key: &'a str,
    passphrase: &'a str,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Response {
    error: String,
    fingerprint: String,
    #[serde(deserialize_with = "base64_bytes::deserialize_secret")]
    data: Zeroizing<Vec<u8>>,
    message: String,
    algorithm: u8,
    #[serde(deserialize_with = "base64_bytes::deserialize_secret")]
    session_key: Zeroizing<Vec<u8>>,
}

/// The bytes of the response to `input`, copied out of Go.
#[allow(unsafe_code)]
fn exchange(input: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut length = 0;
    // SAFETY: Go reads `input` before it returns and keeps no pointer to it; it gives a
    // buffer of `length` bytes allocated with malloc, copied here, then freed by Go.
    unsafe {
        let output = passbolt_gopenpgp_call(input.as_ptr().cast(), input.len(), &raw mut length);
        let bytes =
            Zeroizing::new(std::slice::from_raw_parts(output.cast::<u8>(), length).to_vec());
        passbolt_gopenpgp_free(output);
        bytes
    }
}

/// Run `request` in Go, its failure reported as `error`.
fn call(request: &Request<'_>, error: fn(String) -> CryptoError) -> Result<Response, CryptoError> {
    let input =
        Zeroizing::new(serde_json::to_vec(request).map_err(|failure| error(failure.to_string()))?);
    let mut response: Response = serde_json::from_slice(&exchange(&input))
        .map_err(|failure| error(format!("gopenpgp: {failure}")))?;
    if response.error.is_empty() {
        Ok(response)
    } else {
        Err(error(std::mem::take(&mut response.error)))
    }
}

/// A key Go holds by its armored text, forgotten there with its last handle.
struct GoKey {
    armored: Zeroizing<String>,
}

impl Drop for GoKey {
    fn drop(&mut self) {
        let forget = Request {
            op: "forget",
            armored: &self.armored,
            ..Request::default()
        };
        let _ = call(&forget, CryptoError::KeyParse);
    }
}

fn armored(handle: &KeyHandle) -> Result<&str, CryptoError> {
    Ok(&key_of::<GoKey>(handle)?.armored)
}

fn armored_all<'a>(handles: &[&'a KeyHandle]) -> Result<Vec<&'a str>, CryptoError> {
    handles.iter().map(|handle| armored(handle)).collect()
}

/// The gopenpgp engine: Go runs one operation at a time.
pub struct Gopenpgp;

impl Gopenpgp {
    fn read_key(op: &str, armored: &str) -> Result<(KeyHandle, String), CryptoError> {
        let read = call(
            &Request {
                op,
                armored,
                ..Request::default()
            },
            CryptoError::KeyParse,
        )?;
        let key = GoKey {
            armored: Zeroizing::new(armored.to_owned()),
        };
        Ok((Arc::new(key), read.fingerprint))
    }

    fn decrypted(
        armored_message: &str,
        private_key: &KeyHandle,
        passphrase: &str,
        keep_session_key: bool,
    ) -> Result<Response, CryptoError> {
        let op = if keep_session_key {
            "decryptKeepingSessionKey"
        } else {
            "decrypt"
        };
        let request = Request {
            op,
            message: armored_message,
            key: armored(private_key)?,
            passphrase,
            ..Request::default()
        };
        call(&request, CryptoError::Decrypt)
    }

    fn encrypted(request: &Request<'_>) -> Result<String, CryptoError> {
        Ok(call(request, CryptoError::Encrypt)?.message)
    }
}

impl Engine for Gopenpgp {
    fn name(&self) -> &'static str {
        "gopenpgp"
    }

    fn parse_private_key(&self, armored: &str) -> Result<(KeyHandle, String), CryptoError> {
        Self::read_key("readPrivateKey", armored)
    }

    fn parse_public_key(&self, armored: &str) -> Result<(KeyHandle, String), CryptoError> {
        Self::read_key("readPublicKey", armored)
    }

    fn decrypt<'a>(
        &'a self,
        armored_message: &'a str,
        private_key: &'a KeyHandle,
        passphrase: &'a str,
    ) -> CryptoFuture<'a, Vec<u8>> {
        ready(
            Self::decrypted(armored_message, private_key, passphrase, false)
                .map(|mut decrypted| std::mem::take(&mut *decrypted.data)),
        )
    }

    fn decrypt_keeping_session_key<'a>(
        &'a self,
        armored_message: &'a str,
        private_key: &'a KeyHandle,
        passphrase: &'a str,
    ) -> CryptoFuture<'a, (Vec<u8>, SessionKey)> {
        ready(
            Self::decrypted(armored_message, private_key, passphrase, true).map(|mut decrypted| {
                let key = std::mem::take(&mut *decrypted.session_key);
                (
                    std::mem::take(&mut *decrypted.data),
                    SessionKey::new(decrypted.algorithm, key),
                )
            }),
        )
    }

    fn decrypt_with_session_key<'a>(
        &'a self,
        armored_message: &'a str,
        session_key: &'a SessionKey,
    ) -> CryptoFuture<'a, Vec<u8>> {
        let request = Request {
            op: "decryptWithSessionKey",
            message: armored_message,
            algorithm: session_key.algorithm(),
            session_key: session_key.key(),
            ..Request::default()
        };
        ready(
            call(&request, CryptoError::Decrypt)
                .map(|mut decrypted| std::mem::take(&mut *decrypted.data)),
        )
    }

    fn encrypt<'a>(
        &'a self,
        plaintext: &'a [u8],
        recipients: &'a [&'a KeyHandle],
    ) -> CryptoFuture<'a, String> {
        ready(armored_all(recipients).and_then(|recipients| {
            Self::encrypted(&Request {
                op: "encrypt",
                data: plaintext,
                recipients,
                ..Request::default()
            })
        }))
    }

    fn sign_and_encrypt<'a>(
        &'a self,
        plaintext: &'a str,
        signers: &'a [(&'a KeyHandle, &'a str)],
        recipients: &'a [&'a KeyHandle],
    ) -> CryptoFuture<'a, String> {
        let signed = || {
            let signers = signers
                .iter()
                .map(|(key, passphrase)| {
                    Ok(Signer {
                        key: armored(key)?,
                        passphrase,
                    })
                })
                .collect::<Result<Vec<_>, CryptoError>>()?;
            Self::encrypted(&Request {
                op: "signAndEncrypt",
                text: plaintext,
                signers,
                recipients: armored_all(recipients)?,
                ..Request::default()
            })
        };
        ready(signed())
    }
}
