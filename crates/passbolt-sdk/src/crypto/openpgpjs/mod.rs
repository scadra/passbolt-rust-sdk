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
//! or in WebAssembly the OpenPGP.js of the page. Both run the operations of `engine.js`.
//!
//! OpenPGP.js (LGPL-3.0-or-later) is the unmodified release in `vendor/openpgpjs`.

#[cfg(target_arch = "wasm32")]
mod page;
#[cfg(not(target_arch = "wasm32"))]
mod quickjs;
#[cfg(not(target_arch = "wasm32"))]
mod webcrypto;

#[cfg(target_arch = "wasm32")]
pub use self::page::OpenPgpJs;
#[cfg(not(target_arch = "wasm32"))]
pub use self::quickjs::OpenPgpJs;

/// The name the engine is chosen by.
const NAME: &str = "openpgpjs";

#[cfg(not(target_arch = "wasm32"))]
const ENGINE_JS: &str = include_str!("engine.js");
