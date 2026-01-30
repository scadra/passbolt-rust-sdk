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

//! End-to-end tests: the `passbolt` binary against a real Passbolt server.
//! Run with `scripts/e2e.sh`; settings come from `PASSBOLT_E2E_*` (see `.env.e2e.example`).

mod common;

mod deletions;
mod directory;
mod errors;
mod folder_permissions;
mod folders;
mod interop;
mod outputs;
mod pinning;
mod resource_types;
mod resources;
mod session;
mod session_api;
mod session_keys;
mod sharing;
mod sharing_rules;
mod tools;
mod totp;
