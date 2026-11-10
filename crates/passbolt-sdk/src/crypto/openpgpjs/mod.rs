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

//! The OpenPGP.js engine, the library of the browser extension: run in an embedded `QuickJS`,
//! or in WebAssembly on the OpenPGP.js of the page, else the one the SDK bundles. Both run the
//! operations of `engine.js`. It is the default engine.
//!
//! OpenPGP.js (LGPL-3.0-or-later) is the unmodified release in `vendor/openpgpjs`.

#[cfg(target_arch = "wasm32")]
mod page;
#[cfg(not(target_arch = "wasm32"))]
mod quickjs;
#[cfg(not(target_arch = "wasm32"))]
mod webcrypto;

#[cfg(all(not(target_arch = "wasm32"), not(feature = "gopenpgp")))]
use std::sync::LazyLock;

#[cfg(target_arch = "wasm32")]
pub use self::page::OpenPgpJs;
#[cfg(not(target_arch = "wasm32"))]
pub use self::quickjs::OpenPgpJs;
#[cfg(any(target_arch = "wasm32", not(feature = "gopenpgp")))]
use crate::crypto::OpenPgp;
#[cfg(all(not(target_arch = "wasm32"), not(feature = "gopenpgp")))]
use crate::crypto::{ready, CryptoFuture, Engine, KeyHandle, SessionKey};
#[cfg(all(not(target_arch = "wasm32"), not(feature = "gopenpgp")))]
use crate::error::CryptoError;

/// The name the engine is chosen by.
const NAME: &str = "openpgpjs";

#[cfg(not(target_arch = "wasm32"))]
const ENGINE_JS: &str = include_str!("engine.js");

// Natively, the default engine is gopenpgp when it is built.

/// One JavaScript runtime for the process, started by the first default engine; why it could
/// not start, else.
#[cfg(all(not(target_arch = "wasm32"), not(feature = "gopenpgp")))]
static SHARED: LazyLock<Result<OpenPgp, String>> = LazyLock::new(|| {
    OpenPgpJs::new()
        .map(OpenPgp::new)
        .map_err(|error| error.to_string())
});

/// The engine of `OpenPgp::default()`.
#[cfg(all(not(target_arch = "wasm32"), not(feature = "gopenpgp")))]
pub fn default_engine() -> OpenPgp {
    match &*SHARED {
        Ok(openpgp) => openpgp.clone(),
        Err(reason) => OpenPgp::new(Unavailable(reason.clone())),
    }
}

/// The engine of `OpenPgp::default()`: the OpenPGP.js the SDK bundles.
#[cfg(target_arch = "wasm32")]
pub fn default_engine() -> OpenPgp {
    thread_local! {
        static BUNDLED: OpenPgp = OpenPgp::new(OpenPgpJs::new(&page::bundled()));
    }
    BUNDLED.with(OpenPgp::clone)
}

/// The default engine when its runtime could not start: every operation fails with why.
#[cfg(all(not(target_arch = "wasm32"), not(feature = "gopenpgp")))]
struct Unavailable(String);

#[cfg(all(not(target_arch = "wasm32"), not(feature = "gopenpgp")))]
impl Engine for Unavailable {
    fn name(&self) -> &'static str {
        NAME
    }

    fn parse_private_key(&self, _armored: &str) -> Result<(KeyHandle, String), CryptoError> {
        Err(CryptoError::KeyParse(self.0.clone()))
    }

    fn parse_public_key(&self, _armored: &str) -> Result<(KeyHandle, String), CryptoError> {
        Err(CryptoError::KeyParse(self.0.clone()))
    }

    fn decrypt<'a>(
        &'a self,
        _armored_message: &'a str,
        _private_key: &'a KeyHandle,
        _passphrase: &'a str,
    ) -> CryptoFuture<'a, Vec<u8>> {
        ready(Err(CryptoError::Decrypt(self.0.clone())))
    }

    fn decrypt_keeping_session_key<'a>(
        &'a self,
        _armored_message: &'a str,
        _private_key: &'a KeyHandle,
        _passphrase: &'a str,
    ) -> CryptoFuture<'a, (Vec<u8>, SessionKey)> {
        ready(Err(CryptoError::Decrypt(self.0.clone())))
    }

    fn decrypt_with_session_key<'a>(
        &'a self,
        _armored_message: &'a str,
        _session_key: &'a SessionKey,
    ) -> CryptoFuture<'a, Vec<u8>> {
        ready(Err(CryptoError::Decrypt(self.0.clone())))
    }

    fn encrypt<'a>(
        &'a self,
        _plaintext: &'a [u8],
        _recipients: &'a [&'a KeyHandle],
    ) -> CryptoFuture<'a, String> {
        ready(Err(CryptoError::Encrypt(self.0.clone())))
    }

    fn sign_and_encrypt<'a>(
        &'a self,
        _plaintext: &'a str,
        _signers: &'a [(&'a KeyHandle, &'a str)],
        _recipients: &'a [&'a KeyHandle],
    ) -> CryptoFuture<'a, String> {
        ready(Err(CryptoError::Encrypt(self.0.clone())))
    }
}
