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

//! Passphrases of words of the EFF list, as the browser extension's `PassphraseGenerator`.

use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

use super::random_index;
use crate::error::PassboltError;

/// The 7776 words of the EFF large wordlist, longest first as in the extension: the detection
/// of a passphrase removes them in this order.
pub static WORDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    include_str!("words.txt")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .collect()
});

/// The case of the words of a passphrase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WordCase {
    #[default]
    Lowercase,
    Uppercase,
    /// The first letter of each word in capital: `CorrectHorse`.
    Camelcase,
}

/// How passphrases are generated: the `passphrase_generator_settings` of the password
/// policies. The defaults are the server's and the extension's: 9 lowercase words joined by
/// spaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PassphraseGeneratorSettings {
    pub words: u32,
    pub word_separator: String,
    pub word_case: WordCase,
    /// Bounds of `words`; the server does not send them, the extension's apply.
    pub min_words: u32,
    pub max_words: u32,
}

impl Default for PassphraseGeneratorSettings {
    fn default() -> Self {
        Self {
            words: 9,
            word_separator: " ".into(),
            word_case: WordCase::Lowercase,
            min_words: 4,
            max_words: 40,
        }
    }
}

/// A passphrase following `settings`.
///
/// # Errors
/// `InvalidArgument` with a number of `words` out of `min_words..=max_words`.
pub fn generate_passphrase(
    settings: &PassphraseGeneratorSettings,
) -> Result<String, PassboltError> {
    if !(settings.min_words..=settings.max_words).contains(&settings.words) {
        return Err(PassboltError::InvalidArgument(format!(
            "a passphrase must have between {} and {} words, not {}",
            settings.min_words, settings.max_words, settings.words
        )));
    }
    let words: Vec<String> = (0..settings.words)
        .map(|_| {
            let word = WORDS[random_index(WORDS.len())];
            match settings.word_case {
                WordCase::Lowercase => word.to_string(),
                WordCase::Uppercase => word.to_uppercase(),
                WordCase::Camelcase => capitalized(word),
            }
        })
        .collect();
    Ok(words.join(&settings.word_separator))
}

fn capitalized(word: &str) -> String {
    let mut characters = word.chars();
    characters.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(characters).collect()
    })
}

/// A secret recognized as a passphrase: its number of words and their separator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedPassphrase {
    pub words: usize,
    pub separator: String,
}

/// `secret` as a passphrase: words of the list in any case, joined by one repeated separator.
///
/// `None` for a password. The rules of the extension, edge cases included, so the SDK measures
/// a secret as it does.
#[must_use]
pub fn detect_passphrase(secret: &str) -> Option<DetectedPassphrase> {
    if secret.is_empty() {
        return None;
    }
    // Remove every word of the list, longest first, and count them.
    let mut remaining = secret.to_lowercase();
    let mut words = 0;
    for word in WORDS.iter() {
        let before = remaining.len();
        remaining = remaining.replace(word, "");
        words += (before - remaining.len()) / word.len();
    }

    // n words have n - 1 separators.
    if words == 2 {
        // The text left may be the separator, or what is around two words of a password.
        let password = !secret.contains(&remaining)
            || secret.starts_with(&remaining)
            || secret.ends_with(&remaining);
        return (!password).then_some(DetectedPassphrase {
            words: 2,
            separator: remaining,
        });
    }
    if remaining.is_empty() {
        return Some(DetectedPassphrase {
            words,
            separator: String::new(),
        });
    }
    if words < 3 {
        return None;
    }
    // Lengths in UTF-16 code units, as the extension measures them.
    let separators = words - 1;
    let units: Vec<u16> = remaining.encode_utf16().collect();
    if !units.len().is_multiple_of(separators) {
        return None;
    }
    let separator = String::from_utf16(&units[..units.len() / separators]).ok()?;
    let passphrase = remaining.replace(&separator, "").is_empty()
        && !secret.starts_with(&separator)
        && !secret.ends_with(&separator);
    passphrase.then_some(DetectedPassphrase { words, separator })
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[allow(clippy::unnecessary_wraps)] // the expected value of the table cases
    fn detected(words: usize, separator: &str) -> Option<DetectedPassphrase> {
        Some(DetectedPassphrase {
            words,
            separator: separator.into(),
        })
    }

    #[test]
    fn test_the_list_is_the_eff_large_wordlist() {
        assert_eq!(WORDS.len(), 7776);
        assert_eq!(WORDS.first(), Some(&"abdominal"));
        assert_eq!(WORDS.last(), Some(&"zit"));
    }

    #[test]
    fn test_the_default_passphrase_is_9_lowercase_words_joined_by_spaces() {
        let passphrase = generate_passphrase(&PassphraseGeneratorSettings::default()).unwrap();

        let words: Vec<&str> = passphrase.split(' ').collect();
        assert_eq!(words.len(), 9);
        assert!(
            words.iter().all(|word| WORDS.contains(word)),
            "{passphrase}"
        );
    }

    /// 40 words joined by `_`, which no word holds.
    fn words_in(word_case: WordCase) -> Vec<String> {
        let settings = PassphraseGeneratorSettings {
            words: 40,
            word_separator: "_".into(),
            word_case,
            ..PassphraseGeneratorSettings::default()
        };
        let passphrase = generate_passphrase(&settings).unwrap();
        passphrase.split('_').map(String::from).collect()
    }

    #[test]
    fn test_uppercase_words_are_words_of_the_list_in_capitals() {
        for word in words_in(WordCase::Uppercase) {
            assert!(WORDS.contains(&word.to_lowercase().as_str()), "{word}");
            assert_eq!(word, word.to_uppercase());
        }
    }

    #[test]
    fn test_camelcase_words_start_with_a_capital() {
        for word in words_in(WordCase::Camelcase) {
            let lower = word.to_lowercase();
            assert!(WORDS.contains(&lower.as_str()), "{word}");
            assert_eq!(word, capitalized(&lower));
        }
    }

    #[rstest]
    #[case::too_few(3)]
    #[case::too_many(41)]
    fn test_a_number_of_words_out_of_bounds_is_refused(#[case] words: u32) {
        let settings = PassphraseGeneratorSettings {
            words,
            ..PassphraseGeneratorSettings::default()
        };

        let error = generate_passphrase(&settings).unwrap_err();

        assert!(
            matches!(error, PassboltError::InvalidArgument(_)),
            "{error}"
        );
    }

    // The vectors of the extension's PassphraseGenerator.test.js.
    #[rstest]
    #[case::spaces(
        "answering chirping luckiness android patriarch skinhead cacti ethics",
        detected(8, " ")
    )]
    #[case::uppercase(
        "ANSWERING CHIRPING LUCKINESS ANDROID PATRIARCH SKINHEAD CACTI ETHICS",
        detected(8, " ")
    )]
    #[case::no_separator(
        "answeringchirpingluckinessandroidpatriarchskinheadcactiethics",
        detected(8, "")
    )]
    #[case::special_separator(
        "answering/=\\%[]-chirping/=\\%[]-luckiness/=\\%[]-android/=\\%[]-patriarch/=\\%[]-skinhead/=\\%[]-cacti/=\\%[]-ethics",
        detected(8, "/=\\%[]-")
    )]
    #[case::password("not-a-passhrase-123", None)]
    #[case::two_words_unstructured("step@bolt.", None)]
    #[case::two_words("step@@@@bolt", detected(2, "@@@@"))]
    #[case::starts_with_separator("@stepbolt", None)]
    #[case::ends_with_separator("stepbolt&", None)]
    #[case::one_word("bolt", detected(1, ""))]
    #[case::empty("", None)]
    fn test_a_passphrase_is_detected_as_the_extension_does(
        #[case] secret: &str,
        #[case] expected: Option<DetectedPassphrase>,
    ) {
        assert_eq!(detect_passphrase(secret), expected);
    }

    #[test]
    fn test_a_generated_passphrase_is_detected() {
        let settings = PassphraseGeneratorSettings {
            word_separator: "_".into(),
            word_case: WordCase::Camelcase,
            ..PassphraseGeneratorSettings::default()
        };
        let passphrase = generate_passphrase(&settings).unwrap();

        assert_eq!(
            detect_passphrase(&passphrase),
            detected(9, "_"),
            "{passphrase}"
        );
    }
}
