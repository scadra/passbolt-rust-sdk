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

//! Integration tests, in a single binary to link the crate once.
//! Known bugs are `#[ignore]`d: `cargo test -- --ignored` lists them.

mod common;

mod auth;
mod create_v5;
#[cfg(feature = "interop")]
mod interop;
mod listing;
mod login_errors;
mod metadata;
mod metadata_keys;
mod mfa;
mod pagination;
mod payloads;
mod properties;
mod requests;
mod resources;
mod security;
mod server_identity;
mod session_keys;
mod sharing;
mod totp;
mod transport;
mod update_v5;
mod upgrade;
