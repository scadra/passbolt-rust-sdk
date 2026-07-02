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

//! The OpenPGP.js of the page, in WebAssembly. Keys are read with rpgp, for their fingerprint
//! at once; OpenPGP.js reads and writes the messages, later.

use std::sync::Arc;

use js_sys::{Array, Object, Promise, Reflect, Uint8Array};
use send_wrapper::SendWrapper;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use zeroize::Zeroizing;

use crate::crypto::{key_of, CryptoFuture, Engine, KeyHandle, Rpgp, SessionKey};
use crate::error::CryptoError;

#[wasm_bindgen(module = "/src/crypto/openpgpjs/engine.js")]
extern "C" {
    type JsEngine;

    #[wasm_bindgen(js_name = createEngine)]
    fn create_engine(openpgp: &JsValue) -> JsEngine;

    #[wasm_bindgen(method)]
    fn forget(this: &JsEngine, armored_key: &str);

    #[wasm_bindgen(method, catch)]
    fn decrypt(
        this: &JsEngine,
        armored_message: &str,
        armored_key: &str,
        passphrase: &str,
    ) -> Result<Promise, JsValue>;

    #[wasm_bindgen(method, catch, js_name = decryptKeepingSessionKey)]
    fn decrypt_keeping_session_key(
        this: &JsEngine,
        armored_message: &str,
        armored_key: &str,
        passphrase: &str,
    ) -> Result<Promise, JsValue>;

    #[wasm_bindgen(method, catch, js_name = decryptWithSessionKey)]
    fn decrypt_with_session_key(
        this: &JsEngine,
        armored_message: &str,
        algorithm: u8,
        key: &Uint8Array,
    ) -> Result<Promise, JsValue>;

    #[wasm_bindgen(method, catch)]
    fn encrypt(
        this: &JsEngine,
        binary: &Uint8Array,
        recipients: &Array,
    ) -> Result<Promise, JsValue>;

    #[wasm_bindgen(method, catch, js_name = signAndEncrypt)]
    fn sign_and_encrypt(
        this: &JsEngine,
        text: &str,
        signers: &Array,
        recipients: &Array,
    ) -> Result<Promise, JsValue>;
}

/// WebAssembly runs on one thread: the engine never leaves it.
type Shared = Arc<SendWrapper<JsEngine>>;

/// The OpenPGP.js engine, on the OpenPGP.js of the page.
pub struct OpenPgpJs {
    engine: Shared,
}

/// A key OpenPGP.js holds by its armored text, forgotten there with its last handle.
struct PageKey {
    armored: Zeroizing<String>,
    engine: Shared,
}

impl Drop for PageKey {
    fn drop(&mut self) {
        self.engine.forget(&self.armored);
    }
}

/// The message of what JavaScript threw.
fn reason(value: &JsValue) -> String {
    value
        .dyn_ref::<js_sys::Error>()
        .map(|error| String::from(error.message()))
        .or_else(|| value.as_string())
        .unwrap_or_else(|| format!("{value:?}"))
}

/// The result of `promise`, read by `read`; a failure reported as `error`.
fn settle<'a, T: 'a>(
    promise: Result<Promise, JsValue>,
    error: fn(String) -> CryptoError,
    read: impl FnOnce(JsValue) -> Result<T, String> + 'a,
) -> CryptoFuture<'a, T> {
    Box::pin(SendWrapper::new(async move {
        let promise = promise.map_err(|value| error(reason(&value)))?;
        let value = JsFuture::from(promise)
            .await
            .map_err(|value| error(reason(&value)))?;
        read(value).map_err(error)
    }))
}

fn bytes(value: &JsValue) -> Vec<u8> {
    Uint8Array::new(value).to_vec()
}

fn text(value: &JsValue) -> Result<String, String> {
    value
        .as_string()
        .ok_or_else(|| "OpenPGP.js gave no armored message".into())
}

/// A symmetric algorithm id, a JavaScript number.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // in range, checked first
fn algorithm_of(value: &JsValue) -> Option<u8> {
    value
        .as_f64()
        .filter(|id| id.fract() == 0.0 && (0.0..=f64::from(u8::MAX)).contains(id))
        .map(|id| id as u8)
}

fn field(object: &JsValue, name: &str) -> Result<JsValue, String> {
    Reflect::get(object, &name.into()).map_err(|value| reason(&value))
}

impl OpenPgpJs {
    /// The engine on `openpgp`, the OpenPGP.js module of the page.
    #[must_use]
    pub fn new(openpgp: &JsValue) -> Self {
        Self {
            engine: Arc::new(SendWrapper::new(create_engine(openpgp))),
        }
    }

    /// The armored text of a key this engine holds.
    fn armored<'a>(&self, handle: &'a KeyHandle) -> Result<&'a str, CryptoError> {
        let key: &PageKey = key_of(handle)?;
        if !Arc::ptr_eq(&key.engine, &self.engine) {
            return Err(CryptoError::KeyParse(
                "a key read by another OpenPGP.js engine".into(),
            ));
        }
        Ok(&key.armored)
    }

    fn armored_all(&self, handles: &[&KeyHandle]) -> Result<Array, CryptoError> {
        handles
            .iter()
            .map(|handle| Ok(JsValue::from_str(self.armored(handle)?)))
            .collect()
    }

    /// Read the key with rpgp, for its fingerprint, and hold its armored text.
    fn hold(&self, armored: &str, (_, fingerprint): (KeyHandle, String)) -> (KeyHandle, String) {
        let key = PageKey {
            armored: Zeroizing::new(armored.to_owned()),
            engine: Arc::clone(&self.engine),
        };
        (Arc::new(key), fingerprint)
    }
}

impl Engine for OpenPgpJs {
    fn name(&self) -> &'static str {
        super::NAME
    }

    fn parse_private_key(&self, armored: &str) -> Result<(KeyHandle, String), CryptoError> {
        Ok(self.hold(armored, Rpgp.parse_private_key(armored)?))
    }

    fn parse_public_key(&self, armored: &str) -> Result<(KeyHandle, String), CryptoError> {
        Ok(self.hold(armored, Rpgp.parse_public_key(armored)?))
    }

    fn decrypt<'a>(
        &'a self,
        armored_message: &'a str,
        private_key: &'a KeyHandle,
        passphrase: &'a str,
    ) -> CryptoFuture<'a, Vec<u8>> {
        let promise = match self.armored(private_key) {
            Ok(key) => self.engine.decrypt(armored_message, key, passphrase),
            Err(error) => return crate::crypto::ready(Err(error)),
        };
        settle(promise, CryptoError::Decrypt, |value| Ok(bytes(&value)))
    }

    fn decrypt_keeping_session_key<'a>(
        &'a self,
        armored_message: &'a str,
        private_key: &'a KeyHandle,
        passphrase: &'a str,
    ) -> CryptoFuture<'a, (Vec<u8>, SessionKey)> {
        let promise = match self.armored(private_key) {
            Ok(key) => self
                .engine
                .decrypt_keeping_session_key(armored_message, key, passphrase),
            Err(error) => return crate::crypto::ready(Err(error)),
        };
        settle(promise, CryptoError::Decrypt, |value| {
            let algorithm =
                algorithm_of(&field(&value, "algorithm")?).ok_or("no session key algorithm")?;
            Ok((
                bytes(&field(&value, "data")?),
                SessionKey::new(algorithm, bytes(&field(&value, "key")?)),
            ))
        })
    }

    fn decrypt_with_session_key<'a>(
        &'a self,
        armored_message: &'a str,
        session_key: &'a SessionKey,
    ) -> CryptoFuture<'a, Vec<u8>> {
        let key = Uint8Array::from(session_key.key());
        let promise =
            self.engine
                .decrypt_with_session_key(armored_message, session_key.algorithm(), &key);
        settle(promise, CryptoError::Decrypt, |value| Ok(bytes(&value)))
    }

    fn encrypt<'a>(
        &'a self,
        plaintext: &'a [u8],
        recipients: &'a [&'a KeyHandle],
    ) -> CryptoFuture<'a, String> {
        let promise = match self.armored_all(recipients) {
            Ok(recipients) => self
                .engine
                .encrypt(&Uint8Array::from(plaintext), &recipients),
            Err(error) => return crate::crypto::ready(Err(error)),
        };
        settle(promise, CryptoError::Encrypt, |value| text(&value))
    }

    fn sign_and_encrypt<'a>(
        &'a self,
        plaintext: &'a str,
        signers: &'a [(&'a KeyHandle, &'a str)],
        recipients: &'a [&'a KeyHandle],
    ) -> CryptoFuture<'a, String> {
        let signers = signers
            .iter()
            .map(|(key, passphrase)| {
                let signer = Object::new();
                let set = |name: &str, value: &str| {
                    Reflect::set(&signer, &name.into(), &value.into())
                        .map_err(|value| CryptoError::Encrypt(reason(&value)))
                };
                set("key", self.armored(key)?)?;
                set("passphrase", passphrase)?;
                Ok(JsValue::from(signer))
            })
            .collect::<Result<Array, CryptoError>>();
        let promise = match (signers, self.armored_all(recipients)) {
            (Ok(signers), Ok(recipients)) => {
                self.engine
                    .sign_and_encrypt(plaintext, &signers, &recipients)
            }
            (Err(error), _) | (_, Err(error)) => return crate::crypto::ready(Err(error)),
        };
        settle(promise, CryptoError::Encrypt, |value| text(&value))
    }
}
