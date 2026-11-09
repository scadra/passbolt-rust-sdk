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

//! PIN codes, as the browser extension's `PinCodeGenerator`.

use super::random_index;

/// The shortest PIN code generated.
pub const PIN_CODE_MIN_LENGTH: u32 = 4;
/// The longest PIN code generated.
pub const PIN_CODE_MAX_LENGTH: u32 = 12;

/// A PIN code of `length` digits, brought within 4 to 12 as the extension does.
#[must_use]
pub fn generate_pin_code(length: u32) -> String {
    let length = length.clamp(PIN_CODE_MIN_LENGTH, PIN_CODE_MAX_LENGTH);
    (0..length)
        .map(|_| char::from(b'0' + random_digit()))
        .collect()
}

fn random_digit() -> u8 {
    // An index under 10 always fits.
    u8::try_from(random_index(10)).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::default(4, 4)]
    #[case::longest(12, 12)]
    #[case::too_short(0, 4)]
    #[case::too_long(20, 12)]
    fn test_a_pin_code_has_digits_within_4_and_12(#[case] length: u32, #[case] expected: usize) {
        let pin_code = generate_pin_code(length);

        assert_eq!(pin_code.len(), expected);
        assert!(
            pin_code.bytes().all(|digit| digit.is_ascii_digit()),
            "{pin_code}"
        );
    }
}
