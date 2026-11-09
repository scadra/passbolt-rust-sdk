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

//! Passwords drawn from character sets, as the browser extension's `PasswordGenerator`.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::complexity::{entropy, password_entropy};
use super::random_index;
use crate::error::PassboltError;

/// A character set the generator draws from, named as in the password policies.
pub struct Mask {
    pub characters: &'static [&'static str],
}

pub const UPPER: Mask = Mask {
    characters: &[
        "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R",
        "S", "T", "U", "V", "W", "X", "Y", "Z",
    ],
};
pub const LOWER: Mask = Mask {
    characters: &[
        "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r",
        "s", "t", "u", "v", "w", "x", "y", "z",
    ],
};
pub const DIGIT: Mask = Mask {
    characters: &["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"],
};
pub const CHAR1: Mask = Mask {
    characters: &["#", "$", "%", "&", "@", "^", "~"],
};
pub const PARENTHESIS: Mask = Mask {
    characters: &["{", "(", "[", "|", "]", ")", "}"],
};
pub const CHAR2: Mask = Mask {
    characters: &[".", ",", ":", ";"],
};
pub const CHAR3: Mask = Mask {
    characters: &["'", "\"", "`"],
};
pub const CHAR4: Mask = Mask {
    characters: &["/", "\\", "_", "-"],
};
pub const CHAR5: Mask = Mask {
    characters: &["<", "*", "+", "!", "?", "="],
};
/// The Emoticons block of Unicode 6.
pub const EMOJI: Mask = Mask {
    characters: &[
        "😀", "😁", "😂", "😃", "😄", "😅", "😆", "😇", "😈", "😉", "😊", "😋", "😌", "😍", "😎",
        "😏", "😐", "😑", "😒", "😓", "😔", "😕", "😖", "😗", "😘", "😙", "😚", "😛", "😜", "😝",
        "😞", "😟", "😠", "😡", "😢", "😣", "😤", "😥", "😦", "😧", "😨", "😩", "😪", "😫", "😬",
        "😭", "😮", "😯", "😰", "😱", "😲", "😳", "😴", "😵", "😶", "😷", "😸", "😹", "😺", "😻",
        "😼", "😽", "😾", "😿", "🙀", "🙁", "🙂", "🙃", "🙄", "🙅", "🙆", "🙇", "🙈", "🙉", "🙊",
        "🙋", "🙌", "🙍", "🙎", "🙏",
    ],
};

/// Every set, in the order of the extension: the order of the characters to draw from.
pub const MASKS: [&Mask; 10] = [
    &UPPER,
    &LOWER,
    &DIGIT,
    &CHAR1,
    &PARENTHESIS,
    &CHAR2,
    &CHAR3,
    &CHAR4,
    &CHAR5,
    &EMOJI,
];

/// Characters easy to take for one another, left out with `exclude_look_alike_chars`.
pub const LOOK_ALIKE_CHARACTERS: [&str; 6] = ["O", "l", "|", "I", "0", "1"];

/// How passwords are generated: the `password_generator_settings` of the password policies.
/// The defaults are the server's and the extension's: 18 characters of every set but emoji.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[allow(clippy::struct_excessive_bools)] // the settings of the Passbolt API
pub struct PasswordGeneratorSettings {
    pub length: u32,
    /// Bounds of `length`; the server does not send them, the extension's apply.
    pub min_length: u32,
    pub max_length: u32,
    /// `A-Z`
    pub mask_upper: bool,
    /// `a-z`
    pub mask_lower: bool,
    /// `0-9`
    pub mask_digit: bool,
    /// `{ [ ( | ) ] }`
    pub mask_parenthesis: bool,
    /// The emoticons of Unicode 6.
    pub mask_emoji: bool,
    /// `# $ % & @ ^ ~`
    pub mask_char1: bool,
    /// `. , : ;`
    pub mask_char2: bool,
    /// `'`, `"` and the backtick
    pub mask_char3: bool,
    /// `/ \ _ -`
    pub mask_char4: bool,
    /// `< * + ! ? =`
    pub mask_char5: bool,
    /// Leaves out `O l | I 0 1`.
    pub exclude_look_alike_chars: bool,
}

impl Default for PasswordGeneratorSettings {
    fn default() -> Self {
        Self {
            length: 18,
            min_length: 8,
            max_length: 128,
            mask_upper: true,
            mask_lower: true,
            mask_digit: true,
            mask_parenthesis: true,
            mask_emoji: false,
            mask_char1: true,
            mask_char2: true,
            mask_char3: true,
            mask_char4: true,
            mask_char5: true,
            exclude_look_alike_chars: true,
        }
    }
}

impl PasswordGeneratorSettings {
    /// The characters to draw from: those of the chosen sets, in the order of [`MASKS`].
    pub(crate) fn characters(&self) -> Vec<&'static str> {
        let chosen = [
            self.mask_upper,
            self.mask_lower,
            self.mask_digit,
            self.mask_char1,
            self.mask_parenthesis,
            self.mask_char2,
            self.mask_char3,
            self.mask_char4,
            self.mask_char5,
            self.mask_emoji,
        ];
        MASKS
            .iter()
            .zip(chosen)
            .filter(|(_, chosen)| *chosen)
            .flat_map(|(mask, _)| mask.characters.iter().copied())
            .filter(|character| {
                !self.exclude_look_alike_chars || !LOOK_ALIKE_CHARACTERS.contains(character)
            })
            .collect()
    }

    /// The entropy of the passwords these settings generate, in bits: what the extension shows
    /// before generating.
    #[must_use]
    pub fn max_entropy(&self) -> f64 {
        entropy(self.length as usize, self.characters().len())
    }
}

/// A password following `settings`.
///
/// As the extension, it draws up to 11 passwords and keeps the first whose entropy reaches the
/// one the settings allow, or else the strongest: a draw that misses whole sets is weaker.
///
/// # Errors
/// `InvalidArgument` without any character set, or with a `length` out of
/// `min_length..=max_length`.
pub fn generate_password(settings: &PasswordGeneratorSettings) -> Result<String, PassboltError> {
    let characters = settings.characters();
    if characters.is_empty() {
        return Err(PassboltError::InvalidArgument(
            "the password generator needs at least one character set".into(),
        ));
    }
    if !(settings.min_length..=settings.max_length).contains(&settings.length) {
        return Err(PassboltError::InvalidArgument(format!(
            "the password length must be between {} and {}, not {}",
            settings.min_length, settings.max_length, settings.length
        )));
    }

    let length = settings.length as usize;
    let goal = entropy(length, characters.len()).floor();
    let mut secret = Zeroizing::new(String::new());
    let mut secret_entropy = 0.0;
    for _ in 0..11 {
        let candidate: Zeroizing<String> = Zeroizing::new(
            (0..length)
                .map(|_| characters[random_index(characters.len())])
                .collect(),
        );
        let candidate_entropy = password_entropy(&candidate);
        if candidate_entropy > secret_entropy {
            secret = candidate;
            secret_entropy = candidate_entropy;
        }
        if secret_entropy >= goal {
            break;
        }
    }
    Ok(secret.to_string())
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use unicode_segmentation::UnicodeSegmentation;

    use super::*;

    fn only(set: impl Fn(&mut PasswordGeneratorSettings)) -> PasswordGeneratorSettings {
        let mut settings = PasswordGeneratorSettings {
            mask_upper: false,
            mask_lower: false,
            mask_digit: false,
            mask_parenthesis: false,
            mask_char1: false,
            mask_char2: false,
            mask_char3: false,
            mask_char4: false,
            mask_char5: false,
            exclude_look_alike_chars: false,
            ..PasswordGeneratorSettings::default()
        };
        set(&mut settings);
        settings
    }

    #[test]
    fn test_the_default_password_has_18_characters_of_every_set() {
        let password = generate_password(&PasswordGeneratorSettings::default()).unwrap();

        assert_eq!(password.chars().count(), 18);
        assert!(password_entropy(&password) > 100.0, "{password}");
    }

    #[test]
    fn test_look_alike_characters_are_left_out() {
        let settings = PasswordGeneratorSettings {
            length: 128,
            ..PasswordGeneratorSettings::default()
        };

        let password = generate_password(&settings).unwrap();

        assert!(
            !password.contains(['O', 'l', '|', 'I', '0', '1']),
            "{password}"
        );
    }

    #[rstest]
    #[case::digits(only(|settings| settings.mask_digit = true), "0123456789")]
    #[case::char2(only(|settings| settings.mask_char2 = true), ".,:;")]
    #[case::char4(only(|settings| settings.mask_char4 = true), "/\\_-")]
    fn test_a_password_is_drawn_from_the_chosen_sets_only(
        #[case] settings: PasswordGeneratorSettings,
        #[case] set: &str,
    ) {
        let password = generate_password(&settings).unwrap();

        assert!(
            password.chars().all(|character| set.contains(character)),
            "{password}"
        );
    }

    #[test]
    fn test_an_emoji_counts_as_one_character() {
        let settings = only(|settings| settings.mask_emoji = true);

        let password = generate_password(&settings).unwrap();

        assert_eq!(password.graphemes(true).count(), 18);
        assert!(password
            .graphemes(true)
            .all(|emoji| EMOJI.characters.contains(&emoji)));
    }

    #[test]
    fn test_a_password_without_any_set_is_refused() {
        let error = generate_password(&only(|_| ())).unwrap_err();

        assert!(
            matches!(error, PassboltError::InvalidArgument(_)),
            "{error}"
        );
    }

    #[rstest]
    #[case::too_short(7)]
    #[case::too_long(129)]
    fn test_a_length_out_of_bounds_is_refused(#[case] length: u32) {
        let settings = PasswordGeneratorSettings {
            length,
            ..PasswordGeneratorSettings::default()
        };

        let error = generate_password(&settings).unwrap_err();

        assert!(
            matches!(error, PassboltError::InvalidArgument(_)),
            "{error}"
        );
    }

    #[test]
    fn test_the_max_entropy_counts_the_characters_left() {
        // 26 + 26 + 10 + 7 + 7 + 4 + 3 + 4 + 6 characters, 6 look-alike ones left out: 87.
        let settings = PasswordGeneratorSettings::default();

        let expected = 18.0 * 87f64.log2();

        assert!((settings.max_entropy() - expected).abs() < 1e-9);
    }

    #[test]
    fn test_the_settings_read_from_the_server_keep_the_bounds_of_the_extension() {
        let settings: PasswordGeneratorSettings =
            serde_json::from_str(r#"{"length": 24, "mask_emoji": true}"#).unwrap();

        assert_eq!(settings.length, 24);
        assert!(settings.mask_emoji);
        assert_eq!((settings.min_length, settings.max_length), (8, 128));
    }
}
