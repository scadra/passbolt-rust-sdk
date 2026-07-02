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

//! OpenPGP.js in an embedded `QuickJS` runtime, which runs its promises to their end at once.

use std::sync::{Arc, Mutex, Weak};

use rquickjs::{
    CatchResultExt, CaughtError, Context, Ctx, FromJs, Function, Module, Object, Runtime,
    TypedArray, Value,
};
use zeroize::Zeroizing;

use super::{webcrypto, ENGINE_JS};
use crate::crypto::{key_of, ready, CryptoFuture, Engine, KeyHandle, SessionKey};
use crate::error::CryptoError;

const OPENPGP_JS: &str = include_str!("../../../vendor/openpgpjs/openpgp.min.js");
const WEBCRYPTO_JS: &str = include_str!("webcrypto.js");

/// The stack JavaScript may use, well within the 2 MiB of a Rust thread.
const MAX_STACK_SIZE: usize = 1024 * 1024;

/// A JavaScript runtime with OpenPGP.js loaded, its engine in the global `engine`.
struct Js {
    // Dropped before the runtime.
    context: Context,
    _runtime: Runtime,
}

/// The OpenPGP.js engine: one JavaScript runtime, running one operation at a time.
pub struct OpenPgpJs {
    js: Arc<Mutex<Js>>,
}

/// A key the runtime holds by its armored text, forgotten there with its last handle.
struct JsKey {
    armored: Zeroizing<String>,
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
            let _ = call::<()>(&ctx, "forget", (self.armored.as_str(),));
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

/// Call the operation `name` of the engine, waiting for the promise it gives if any.
fn call<'js, T: FromJs<'js>>(
    ctx: &Ctx<'js>,
    name: &str,
    args: impl rquickjs::function::IntoArgs<'js>,
) -> Result<T, String> {
    let run = || -> rquickjs::Result<T> {
        let engine: Object = ctx.globals().get("engine")?;
        let function: Function = engine.get(name)?;
        let value: Value = function.call(args)?;
        if let Some(promise) = value.as_promise() {
            return promise.finish();
        }
        T::from_js(ctx, value)
    };
    run().catch(ctx).map_err(message)
}

fn bytes<'js>(ctx: &Ctx<'js>, data: &[u8]) -> Result<TypedArray<'js, u8>, String> {
    TypedArray::new_copy(ctx.clone(), data).map_err(|error| error.to_string())
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
                let load = || -> rquickjs::Result<()> {
                    let native = Object::new(ctx.clone())?;
                    webcrypto::install(&ctx, &native)?;
                    ctx.globals().set("native", native)?;
                    ctx.eval::<(), _>(WEBCRYPTO_JS)?;
                    ctx.eval::<(), _>(OPENPGP_JS)?;
                    let (module, evaluated) =
                        Module::declare(ctx.clone(), "engine.js", ENGINE_JS)?.eval()?;
                    evaluated.finish::<()>()?;
                    let create_engine: Function = module.get("createEngine")?;
                    let openpgp: Value = ctx.globals().get("openpgp")?;
                    let engine: Object = create_engine.call((openpgp,))?;
                    ctx.globals().set("engine", engine)
                };
                load().catch(&ctx).map_err(message)
            })
            .map_err(failure)?;
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

    /// The armored text of a key this runtime holds.
    fn armored<'a>(&self, handle: &'a KeyHandle) -> Result<&'a str, CryptoError> {
        let key: &JsKey = key_of(handle)?;
        if !Weak::ptr_eq(&key.js, &Arc::downgrade(&self.js)) {
            return Err(CryptoError::KeyParse(
                "a key read by another OpenPGP.js engine".into(),
            ));
        }
        Ok(&key.armored)
    }

    fn armored_all<'a>(&self, handles: &[&'a KeyHandle]) -> Result<Vec<&'a str>, CryptoError> {
        handles.iter().map(|handle| self.armored(handle)).collect()
    }

    fn read_key(&self, operation: &str, armored: &str) -> Result<(KeyHandle, String), CryptoError> {
        let fingerprint = self.run(CryptoError::KeyParse, |ctx| {
            call::<String>(ctx, operation, (armored,))
        })?;
        let key = JsKey {
            armored: Zeroizing::new(armored.to_owned()),
            js: Arc::downgrade(&self.js),
        };
        Ok((Arc::new(key), fingerprint))
    }

    fn decrypted(
        &self,
        armored_message: &str,
        private_key: &KeyHandle,
        passphrase: &str,
    ) -> Result<Vec<u8>, CryptoError> {
        let key = self.armored(private_key)?;
        self.run(CryptoError::Decrypt, |ctx| {
            let data: TypedArray<u8> = call(ctx, "decrypt", (armored_message, key, passphrase))?;
            Ok(webcrypto::bytes(&data))
        })
    }

    fn decrypted_keeping_session_key(
        &self,
        armored_message: &str,
        private_key: &KeyHandle,
        passphrase: &str,
    ) -> Result<(Vec<u8>, SessionKey), CryptoError> {
        let key = self.armored(private_key)?;
        self.run(CryptoError::Decrypt, |ctx| {
            let decrypted: Object = call(
                ctx,
                "decryptKeepingSessionKey",
                (armored_message, key, passphrase),
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

    fn decrypted_with_session_key(
        &self,
        armored_message: &str,
        session_key: &SessionKey,
    ) -> Result<Vec<u8>, CryptoError> {
        self.run(CryptoError::Decrypt, |ctx| {
            let key = bytes(ctx, session_key.key())?;
            let data: TypedArray<u8> = call(
                ctx,
                "decryptWithSessionKey",
                (armored_message, session_key.algorithm(), key),
            )?;
            Ok(webcrypto::bytes(&data))
        })
    }

    fn encrypted(
        &self,
        plaintext: &[u8],
        recipients: &[&KeyHandle],
    ) -> Result<String, CryptoError> {
        let recipients = self.armored_all(recipients)?;
        self.run(CryptoError::Encrypt, |ctx| {
            call(ctx, "encrypt", (bytes(ctx, plaintext)?, recipients))
        })
    }

    fn signed_and_encrypted(
        &self,
        plaintext: &str,
        signers: &[(&KeyHandle, &str)],
        recipients: &[&KeyHandle],
    ) -> Result<String, CryptoError> {
        let signers = signers
            .iter()
            .map(|(key, passphrase)| Ok((self.armored(key)?, *passphrase)))
            .collect::<Result<Vec<_>, CryptoError>>()?;
        let recipients = self.armored_all(recipients)?;
        self.run(CryptoError::Encrypt, |ctx| {
            let signers = signers
                .iter()
                .map(|(key, passphrase)| {
                    let signer = Object::new(ctx.clone())?;
                    signer.set("key", *key)?;
                    signer.set("passphrase", *passphrase)?;
                    Ok(signer)
                })
                .collect::<rquickjs::Result<Vec<_>>>()
                .map_err(|error| error.to_string())?;
            call(ctx, "signAndEncrypt", (plaintext, signers, recipients))
        })
    }
}

impl Engine for OpenPgpJs {
    fn name(&self) -> &'static str {
        super::NAME
    }

    fn parse_private_key(&self, armored: &str) -> Result<(KeyHandle, String), CryptoError> {
        self.read_key("readPrivateKey", armored)
    }

    fn parse_public_key(&self, armored: &str) -> Result<(KeyHandle, String), CryptoError> {
        self.read_key("readPublicKey", armored)
    }

    fn decrypt<'a>(
        &'a self,
        armored_message: &'a str,
        private_key: &'a KeyHandle,
        passphrase: &'a str,
    ) -> CryptoFuture<'a, Vec<u8>> {
        ready(self.decrypted(armored_message, private_key, passphrase))
    }

    fn decrypt_keeping_session_key<'a>(
        &'a self,
        armored_message: &'a str,
        private_key: &'a KeyHandle,
        passphrase: &'a str,
    ) -> CryptoFuture<'a, (Vec<u8>, SessionKey)> {
        ready(self.decrypted_keeping_session_key(armored_message, private_key, passphrase))
    }

    fn decrypt_with_session_key<'a>(
        &'a self,
        armored_message: &'a str,
        session_key: &'a SessionKey,
    ) -> CryptoFuture<'a, Vec<u8>> {
        ready(self.decrypted_with_session_key(armored_message, session_key))
    }

    fn encrypt<'a>(
        &'a self,
        plaintext: &'a [u8],
        recipients: &'a [&'a KeyHandle],
    ) -> CryptoFuture<'a, String> {
        ready(self.encrypted(plaintext, recipients))
    }

    fn sign_and_encrypt<'a>(
        &'a self,
        plaintext: &'a str,
        signers: &'a [(&'a KeyHandle, &'a str)],
        recipients: &'a [&'a KeyHandle],
    ) -> CryptoFuture<'a, String> {
        ready(self.signed_and_encrypted(plaintext, signers, recipients))
    }
}
