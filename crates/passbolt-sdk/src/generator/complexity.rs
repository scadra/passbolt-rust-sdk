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

//! The entropy and strength of a secret, computed as the browser extension's
//! `SecretGeneratorComplexity` does, so both show the same strength.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use unicode_segmentation::UnicodeSegmentation;

use super::passphrase::{detect_passphrase, WORDS};
use super::password::MASKS;

/// The cases a passphrase word may have: they multiply the words to guess from.
const WORD_CASES: usize = 3;

/// The strength the extension shows for an entropy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Strength {
    /// No secret; `not_available`, the id of the extension.
    #[serde(rename = "not_available")]
    NotAvailable,
    /// Under 60 bits.
    VeryWeak,
    /// From 60 bits.
    Weak,
    /// From 80 bits.
    Fair,
    /// From 112 bits.
    Strong,
    /// From 128 bits.
    VeryStrong,
}

impl Strength {
    /// The strength of `entropy` bits.
    #[must_use]
    pub fn of(entropy: f64) -> Self {
        match entropy {
            entropy if entropy >= 128.0 => Self::VeryStrong,
            entropy if entropy >= 112.0 => Self::Strong,
            entropy if entropy >= 80.0 => Self::Fair,
            entropy if entropy >= 60.0 => Self::Weak,
            entropy if entropy >= 1.0 => Self::VeryWeak,
            _ => Self::NotAvailable,
        }
    }

    /// The label of the extension: `Very weak`, `Strong`…
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotAvailable => "N/A",
            Self::VeryWeak => "Very weak",
            Self::Weak => "Weak",
            Self::Fair => "Fair",
            Self::Strong => "Strong",
            Self::VeryStrong => "Very strong",
        }
    }
}

/// `length` symbols drawn from `possibilities`, in bits.
pub fn entropy(length: usize, possibilities: usize) -> f64 {
    if length == 0 || possibilities == 0 {
        return 0.0;
    }
    #[allow(clippy::cast_precision_loss)] // lengths and sets far under 2^52
    let bits = length as f64 * (possibilities as f64).log2();
    bits
}

/// The entropy of a password: each character set it uses counts whole, each character out of
/// the sets counts once.
pub fn password_entropy(password: &str) -> f64 {
    let characters: Vec<&str> = password.graphemes(true).collect();
    let mut possibilities: usize = MASKS
        .iter()
        .filter(|mask| {
            characters
                .iter()
                .any(|character| mask.characters.contains(character))
        })
        .map(|mask| mask.characters.len())
        .sum();
    let unknown: HashSet<&&str> = characters
        .iter()
        .filter(|character| !MASKS.iter().any(|mask| mask.characters.contains(character)))
        .collect();
    possibilities += unknown.len();
    entropy(characters.len(), possibilities)
}

/// The entropy of a passphrase of `words` words of the list, in any of the 3 cases, joined by
/// `separator`.
pub fn passphrase_entropy(words: usize, separator: &str) -> f64 {
    entropy(words, WORDS.len() * WORD_CASES) + password_entropy(separator)
}

/// The entropy of `secret` in bits: as a passphrase when it is words of the list joined by one
/// separator, as a password otherwise.
#[must_use]
pub fn secret_entropy(secret: &str) -> f64 {
    detect_passphrase(secret).map_or_else(
        || password_entropy(secret),
        |passphrase| passphrase_entropy(passphrase.words, &passphrase.separator),
    )
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    fn close(left: f64, right: f64) -> bool {
        (left - right).abs() < 1e-9
    }

    #[rstest]
    #[case::none(0.0, Strength::NotAvailable)]
    #[case::under_a_bit(0.5, Strength::NotAvailable)]
    #[case::very_weak(59.9, Strength::VeryWeak)]
    #[case::weak(60.0, Strength::Weak)]
    #[case::fair(80.0, Strength::Fair)]
    #[case::strong(112.0, Strength::Strong)]
    #[case::very_strong(128.0, Strength::VeryStrong)]
    fn test_the_strength_follows_the_thresholds_of_the_extension(
        #[case] entropy: f64,
        #[case] strength: Strength,
    ) {
        assert_eq!(Strength::of(entropy), strength);
    }

    /// Rounded to 2 decimals, as the extension's tests compare them.
    fn rounded(bits: f64) -> f64 {
        (bits * 100.0).round() / 100.0
    }

    // The vectors of the extension's SecretGeneratorComplexity.test.js.
    #[rstest]
    #[case::lower("aaaaaa", 28.2)]
    #[case::upper("AAAAAA", 28.2)]
    #[case::digits("111111", 19.93)]
    #[case::parenthesis("((((((", 16.84)]
    #[case::char1("#$%&@^~", 19.65)]
    #[case::char2(".,:;", 8.0)]
    #[case::char5("<*+!?=", 15.51)]
    #[case::three_sets("aaaAAA1111", 59.54)]
    #[case::unknown_flag("🇫🇷", 0.0)]
    #[case::emoji("😸😸😸😸😸😸😸😸", 50.58)]
    #[case::emoji_and_flag("😸😸😸😸😸😸😸🇫🇷", 50.72)]
    #[case::every_set("aA1(~:<😸", 59.0)]
    fn test_the_password_entropy_is_the_extensions(#[case] password: &str, #[case] bits: f64) {
        assert!(
            close(rounded(password_entropy(password)), bits),
            "{password}"
        );
    }

    #[rstest]
    #[case::five_words(5, "", 72.55)]
    #[case::five_words_and_separator(5, "; ", 77.19)]
    #[case::ten_words(10, "", 145.1)]
    #[case::ten_words_and_separator(10, "; ", 149.74)]
    fn test_the_passphrase_entropy_is_the_extensions(
        #[case] words: usize,
        #[case] separator: &str,
        #[case] bits: f64,
    ) {
        assert!(close(rounded(passphrase_entropy(words, separator)), bits));
    }

    #[test]
    fn test_a_secret_made_of_words_is_measured_as_a_passphrase() {
        let bits = secret_entropy("abdominal acclimate accompany activator");

        assert!(close(bits, passphrase_entropy(4, " ")));
    }
}
