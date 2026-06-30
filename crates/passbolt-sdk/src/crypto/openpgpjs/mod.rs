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

//! The OpenPGP.js engine: the library of the browser extension, run in an embedded `QuickJS`.
//!
//! OpenPGP.js (LGPL-3.0-or-later) is the unmodified release in `vendor/openpgpjs`.

mod webcrypto;

use std::sync::{Arc, Mutex, Weak};

use rquickjs::{
    CatchResultExt, CaughtError, Context, Ctx, FromJs, Object, Runtime, TypedArray, Value,
};

use super::{key_of, Engine, KeyHandle, SessionKey};
use crate::error::CryptoError;

const OPENPGP_JS: &str = include_str!("../../../vendor/openpgpjs/openpgp.min.js");
const WEBCRYPTO_JS: &str = include_str!("webcrypto.js");
const ENGINE_JS: &str = include_str!("engine.js");

/// The stack JavaScript may use, well within the 2 MiB of a Rust thread.
const MAX_STACK_SIZE: usize = 1024 * 1024;

/// A JavaScript runtime with OpenPGP.js loaded.
struct Js {
    // Dropped after the context.
    context: Context,
    _runtime: Runtime,
}

/// The OpenPGP.js engine: one JavaScript runtime, running one operation at a time.
pub struct OpenPgpJs {
    js: Arc<Mutex<Js>>,
}

/// A key the JavaScript runtime holds, forgotten there with its last handle.
struct JsKey {
    id: u32,
    js: Weak<Mutex<Js>>,
}

impl Drop for JsKey {
    fn drop(&mut self) {
        let Some(js) = self.js.upgrade() else {
            return;
        };
        let Ok(js) = js.lock() else {
            return;
        };
        js.context.with(|ctx| {
            let _ = call::<()>(&ctx, "forget", (self.id,));
        });
    }
}

/// The message of what JavaScript threw.
fn message(error: CaughtError<'_>) -> String {
    match error {
        CaughtError::Exception(exception) => exception.message().unwrap_or_default(),
        error => error.to_string(),
    }
}

/// Call the global function `name`, waiting for the promise it gives if any.
fn call<'js, T: FromJs<'js>>(
    ctx: &Ctx<'js>,
    name: &str,
    args: impl rquickjs::function::IntoArgs<'js>,
) -> Result<T, String> {
    let run = || -> rquickjs::Result<T> {
        let function: rquickjs::Function = ctx.globals().get(name)?;
        let value: Value = function.call(args)?;
        if let Some(promise) = value.as_promise() {
            return promise.finish();
        }
        T::from_js(ctx, value)
    };
    run().catch(ctx).map_err(message)
}

fn bytes<'js>(ctx: &Ctx<'js>, data: &[u8]) -> rquickjs::Result<TypedArray<'js, u8>> {
    TypedArray::new_copy(ctx.clone(), data)
}

impl OpenPgpJs {
    /// Start a JavaScript runtime and load OpenPGP.js in it.
    pub fn new() -> Result<Self, CryptoError> {
        let failure = |reason: String| CryptoError::KeyParse(format!("OpenPGP.js: {reason}"));
        let runtime = Runtime::new().map_err(|error| failure(error.to_string()))?;
        runtime.set_max_stack_size(MAX_STACK_SIZE);
        let context = Context::full(&runtime).map_err(|error| failure(error.to_string()))?;
        context
            .with(|ctx| {
                let native = Object::new(ctx.clone())?;
                webcrypto::install(&ctx, &native)?;
                ctx.globals().set("native", native)?;
                ctx.eval::<(), _>(WEBCRYPTO_JS)?;
                ctx.eval::<(), _>(OPENPGP_JS)?;
                ctx.eval::<(), _>(ENGINE_JS)
            })
            .map_err(|error| failure(error.to_string()))?;
        Ok(Self {
            js: Arc::new(Mutex::new(Js {
                context,
                _runtime: runtime,
            })),
        })
    }

    /// Run `operation` in the runtime, its failure reported as `error`.
    fn run<T>(
        &self,
        error: fn(String) -> CryptoError,
        operation: impl for<'js> FnOnce(&Ctx<'js>) -> Result<T, String>,
    ) -> Result<T, CryptoError> {
        let js = self
            .js
            .lock()
            .map_err(|_| error("the OpenPGP.js runtime failed".into()))?;
        js.context.with(|ctx| operation(&ctx)).map_err(error)
    }

    /// The id of a key this runtime holds.
    fn id_of(&self, handle: &KeyHandle) -> Result<u32, CryptoError> {
        let key: &JsKey = key_of(handle)?;
        if !Weak::ptr_eq(&key.js, &Arc::downgrade(&self.js)) {
            return Err(CryptoError::KeyParse(
                "a key read by another OpenPGP.js engine".into(),
            ));
        }
        Ok(key.id)
    }

    fn read_key(&self, function: &str, armored: &str) -> Result<(KeyHandle, String), CryptoError> {
        let (id, fingerprint) = self.run(CryptoError::KeyParse, |ctx| {
            let key: Object = call(ctx, function, (armored,))?;
            let id = key.get("id").map_err(|error| error.to_string())?;
            let fingerprint = key.get("fingerprint").map_err(|error| error.to_string())?;
            Ok((id, fingerprint))
        })?;
        let key = JsKey {
            id,
            js: Arc::downgrade(&self.js),
        };
        Ok((Arc::new(key), fingerprint))
    }
}

impl Engine for OpenPgpJs {
    fn name(&self) -> &'static str {
        "openpgpjs"
    }

    fn parse_private_key(&self, armored: &str) -> Result<(KeyHandle, String), CryptoError> {
        self.read_key("readPrivateKey", armored)
    }

    fn parse_public_key(&self, armored: &str) -> Result<(KeyHandle, String), CryptoError> {
        self.read_key("readPublicKey", armored)
    }

    fn decrypt(
        &self,
        armored_message: &str,
        private_key: &KeyHandle,
        passphrase: &str,
    ) -> Result<Vec<u8>, CryptoError> {
        let id = self.id_of(private_key)?;
        self.run(CryptoError::Decrypt, |ctx| {
            let data: TypedArray<u8> = call(ctx, "decrypt", (armored_message, id, passphrase))?;
            Ok(webcrypto::bytes(&data))
        })
    }

    fn decrypt_keeping_session_key(
        &self,
        armored_message: &str,
        private_key: &KeyHandle,
        passphrase: &str,
    ) -> Result<(Vec<u8>, SessionKey), CryptoError> {
        let id = self.id_of(private_key)?;
        self.run(CryptoError::Decrypt, |ctx| {
            let decrypted: Object = call(
                ctx,
                "decryptKeepingSessionKey",
                (armored_message, id, passphrase),
            )?;
            let read = || -> rquickjs::Result<(Vec<u8>, SessionKey)> {
                let data: TypedArray<u8> = decrypted.get("data")?;
                let key: TypedArray<u8> = decrypted.get("key")?;
                let algorithm: u8 = decrypted.get("algorithm")?;
                Ok((
                    webcrypto::bytes(&data),
                    SessionKey::new(algorithm, webcrypto::bytes(&key)),
                ))
            };
            read().map_err(|error| error.to_string())
        })
    }

    fn decrypt_with_session_key(
        &self,
        armored_message: &str,
        session_key: &SessionKey,
    ) -> Result<Vec<u8>, CryptoError> {
        self.run(CryptoError::Decrypt, |ctx| {
            let key = bytes(ctx, session_key.key()).map_err(|error| error.to_string())?;
            let data: TypedArray<u8> = call(
                ctx,
                "decryptWithSessionKey",
                (armored_message, session_key.algorithm(), key),
            )?;
            Ok(webcrypto::bytes(&data))
        })
    }

    fn encrypt(&self, plaintext: &[u8], recipients: &[&KeyHandle]) -> Result<String, CryptoError> {
        let ids = recipients
            .iter()
            .map(|recipient| self.id_of(recipient))
            .collect::<Result<Vec<_>, _>>()?;
        self.run(CryptoError::Encrypt, |ctx| {
            let data = bytes(ctx, plaintext).map_err(|error| error.to_string())?;
            call(ctx, "encrypt", (data, ids))
        })
    }

    fn sign_and_encrypt(
        &self,
        plaintext: &str,
        signers: &[(&KeyHandle, &str)],
        recipients: &[&KeyHandle],
    ) -> Result<String, CryptoError> {
        let signers = signers
            .iter()
            .map(|(key, passphrase)| Ok((self.id_of(key)?, *passphrase)))
            .collect::<Result<Vec<_>, CryptoError>>()?;
        let ids = recipients
            .iter()
            .map(|recipient| self.id_of(recipient))
            .collect::<Result<Vec<_>, _>>()?;
        self.run(CryptoError::Encrypt, |ctx| {
            let signers = signers
                .iter()
                .map(|(id, passphrase)| {
                    let signer = Object::new(ctx.clone())?;
                    signer.set("id", *id)?;
                    signer.set("passphrase", *passphrase)?;
                    Ok(signer)
                })
                .collect::<rquickjs::Result<Vec<_>>>()
                .map_err(|error| error.to_string())?;
            call(ctx, "signAndEncrypt", (plaintext, signers, ids))
        })
    }
}
