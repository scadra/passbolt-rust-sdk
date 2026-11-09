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

//! Passwords, passphrases and PIN codes generated as the browser extension generates them,
//! and their strength measured as it does.

mod complexity;
mod passphrase;
mod password;
mod pin;

pub use complexity::{secret_entropy, Strength};
pub use passphrase::{
    detect_passphrase, generate_passphrase, DetectedPassphrase, PassphraseGeneratorSettings,
    WordCase,
};
pub use password::{generate_password, PasswordGeneratorSettings};
pub use pin::{generate_pin_code, PIN_CODE_MAX_LENGTH, PIN_CODE_MIN_LENGTH};

use rand::Rng;

/// An index under `len`, uniform, from the operating system's generator (the Web Crypto API
/// in a browser).
pub(crate) fn random_index(len: usize) -> usize {
    rand::rngs::OsRng.gen_range(0..len)
}
