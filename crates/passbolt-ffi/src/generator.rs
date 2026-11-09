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

//! Passwords, passphrases and PIN codes generated as the browser extension generates them.
//!
//! `UniFFI` defaults are literals only: the settings records default each field, the
//! policies, which hold records, come from [`default_password_policies`] or the server.

use passbolt_sdk::generator;

use crate::error::PassboltError;

/// How passwords are generated; the defaults are the server's and the extension's: 18
/// characters of every set but emoji, without look-alike characters.
#[derive(uniffi::Record)]
#[allow(clippy::struct_excessive_bools)] // the settings of the Passbolt API
pub struct PasswordGeneratorSettings {
    #[uniffi(default = 18)]
    pub length: u32,
    #[uniffi(default = 8)]
    pub min_length: u32,
    #[uniffi(default = 128)]
    pub max_length: u32,
    /// `A-Z`
    #[uniffi(default = true)]
    pub mask_upper: bool,
    /// `a-z`
    #[uniffi(default = true)]
    pub mask_lower: bool,
    /// `0-9`
    #[uniffi(default = true)]
    pub mask_digit: bool,
    /// `{ [ ( | ) ] }`
    #[uniffi(default = true)]
    pub mask_parenthesis: bool,
    /// The emoticons of Unicode 6.
    #[uniffi(default = false)]
    pub mask_emoji: bool,
    /// `# $ % & @ ^ ~`
    #[uniffi(default = true)]
    pub mask_char1: bool,
    /// `. , : ;`
    #[uniffi(default = true)]
    pub mask_char2: bool,
    /// `'`, `"` and the backtick
    #[uniffi(default = true)]
    pub mask_char3: bool,
    /// `/ \ _ -`
    #[uniffi(default = true)]
    pub mask_char4: bool,
    /// `< * + ! ? =`
    #[uniffi(default = true)]
    pub mask_char5: bool,
    /// Leaves out `O l | I 0 1`.
    #[uniffi(default = true)]
    pub exclude_look_alike_chars: bool,
}

/// The case of the words of a passphrase.
#[derive(uniffi::Enum, Clone, Copy)]
pub enum WordCase {
    Lowercase,
    Uppercase,
    /// The first letter of each word in capital.
    Camelcase,
}

/// How passphrases are generated; the defaults are the server's and the extension's: 9
/// lowercase words of the EFF list joined by spaces.
#[derive(uniffi::Record)]
pub struct PassphraseGeneratorSettings {
    #[uniffi(default = 9)]
    pub words: u32,
    #[uniffi(default = " ")]
    pub word_separator: String,
    /// `None` is lowercase.
    #[uniffi(default = None)]
    pub word_case: Option<WordCase>,
    #[uniffi(default = 4)]
    pub min_words: u32,
    #[uniffi(default = 40)]
    pub max_words: u32,
}

/// What the generator makes by default.
#[derive(uniffi::Enum, Clone, Copy)]
pub enum GeneratorType {
    Password,
    Passphrase,
}

/// The password policies of the organization: the generator to use and its settings.
#[derive(uniffi::Record)]
pub struct PasswordPolicies {
    pub default_generator: GeneratorType,
    pub password_generator_settings: PasswordGeneratorSettings,
    pub passphrase_generator_settings: PassphraseGeneratorSettings,
    /// Check new passwords against Have I Been Pwned.
    #[uniffi(default = true)]
    pub external_dictionary_check: bool,
    /// Where the server read them: `default`, `file`, `env`, `db`…
    #[uniffi(default = None)]
    pub source: Option<String>,
    /// Set once an administrator saved them (Passbolt Pro).
    #[uniffi(default = None)]
    pub id: Option<String>,
}

/// The strength the extension shows for a secret.
#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Strength {
    /// No secret.
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

impl From<generator::PasswordGeneratorSettings> for PasswordGeneratorSettings {
    fn from(settings: generator::PasswordGeneratorSettings) -> Self {
        Self {
            length: settings.length,
            min_length: settings.min_length,
            max_length: settings.max_length,
            mask_upper: settings.mask_upper,
            mask_lower: settings.mask_lower,
            mask_digit: settings.mask_digit,
            mask_parenthesis: settings.mask_parenthesis,
            mask_emoji: settings.mask_emoji,
            mask_char1: settings.mask_char1,
            mask_char2: settings.mask_char2,
            mask_char3: settings.mask_char3,
            mask_char4: settings.mask_char4,
            mask_char5: settings.mask_char5,
            exclude_look_alike_chars: settings.exclude_look_alike_chars,
        }
    }
}

impl From<PasswordGeneratorSettings> for generator::PasswordGeneratorSettings {
    fn from(settings: PasswordGeneratorSettings) -> Self {
        Self {
            length: settings.length,
            min_length: settings.min_length,
            max_length: settings.max_length,
            mask_upper: settings.mask_upper,
            mask_lower: settings.mask_lower,
            mask_digit: settings.mask_digit,
            mask_parenthesis: settings.mask_parenthesis,
            mask_emoji: settings.mask_emoji,
            mask_char1: settings.mask_char1,
            mask_char2: settings.mask_char2,
            mask_char3: settings.mask_char3,
            mask_char4: settings.mask_char4,
            mask_char5: settings.mask_char5,
            exclude_look_alike_chars: settings.exclude_look_alike_chars,
        }
    }
}

impl From<generator::WordCase> for WordCase {
    fn from(word_case: generator::WordCase) -> Self {
        match word_case {
            generator::WordCase::Lowercase => Self::Lowercase,
            generator::WordCase::Uppercase => Self::Uppercase,
            generator::WordCase::Camelcase => Self::Camelcase,
        }
    }
}

impl From<WordCase> for generator::WordCase {
    fn from(word_case: WordCase) -> Self {
        match word_case {
            WordCase::Lowercase => Self::Lowercase,
            WordCase::Uppercase => Self::Uppercase,
            WordCase::Camelcase => Self::Camelcase,
        }
    }
}

impl From<generator::PassphraseGeneratorSettings> for PassphraseGeneratorSettings {
    fn from(settings: generator::PassphraseGeneratorSettings) -> Self {
        Self {
            words: settings.words,
            word_separator: settings.word_separator,
            word_case: Some(settings.word_case.into()),
            min_words: settings.min_words,
            max_words: settings.max_words,
        }
    }
}

impl From<PassphraseGeneratorSettings> for generator::PassphraseGeneratorSettings {
    fn from(settings: PassphraseGeneratorSettings) -> Self {
        Self {
            words: settings.words,
            word_separator: settings.word_separator,
            word_case: settings.word_case.map(Into::into).unwrap_or_default(),
            min_words: settings.min_words,
            max_words: settings.max_words,
        }
    }
}

impl From<generator::GeneratorType> for GeneratorType {
    fn from(generator_type: generator::GeneratorType) -> Self {
        match generator_type {
            generator::GeneratorType::Password => Self::Password,
            generator::GeneratorType::Passphrase => Self::Passphrase,
        }
    }
}

impl From<GeneratorType> for generator::GeneratorType {
    fn from(generator_type: GeneratorType) -> Self {
        match generator_type {
            GeneratorType::Password => Self::Password,
            GeneratorType::Passphrase => Self::Passphrase,
        }
    }
}

impl From<generator::PasswordPolicies> for PasswordPolicies {
    fn from(policies: generator::PasswordPolicies) -> Self {
        Self {
            default_generator: policies.default_generator.into(),
            password_generator_settings: policies.password_generator_settings.into(),
            passphrase_generator_settings: policies.passphrase_generator_settings.into(),
            external_dictionary_check: policies.external_dictionary_check,
            source: policies.source,
            id: policies.id,
        }
    }
}

impl From<PasswordPolicies> for generator::PasswordPolicies {
    fn from(policies: PasswordPolicies) -> Self {
        Self {
            default_generator: policies.default_generator.into(),
            password_generator_settings: policies.password_generator_settings.into(),
            passphrase_generator_settings: policies.passphrase_generator_settings.into(),
            external_dictionary_check: policies.external_dictionary_check,
            source: policies.source,
            id: policies.id,
            ..Self::default()
        }
    }
}

impl From<generator::Strength> for Strength {
    fn from(strength: generator::Strength) -> Self {
        match strength {
            generator::Strength::NotAvailable => Self::NotAvailable,
            generator::Strength::VeryWeak => Self::VeryWeak,
            generator::Strength::Weak => Self::Weak,
            generator::Strength::Fair => Self::Fair,
            generator::Strength::Strong => Self::Strong,
            generator::Strength::VeryStrong => Self::VeryStrong,
        }
    }
}

/// The policies of a server without settings: passwords of 18 characters by default.
#[uniffi::export]
#[must_use]
pub fn default_password_policies() -> PasswordPolicies {
    generator::PasswordPolicies::default().into()
}

/// A password following `settings`, as the extension generates it.
#[uniffi::export]
pub fn generate_password(settings: PasswordGeneratorSettings) -> Result<String, PassboltError> {
    Ok(generator::generate_password(&settings.into())?)
}

/// A passphrase of words of the EFF list following `settings`.
#[uniffi::export]
pub fn generate_passphrase(settings: PassphraseGeneratorSettings) -> Result<String, PassboltError> {
    Ok(generator::generate_passphrase(&settings.into())?)
}

/// A secret from the default generator of `policies`, those of
/// [`PassboltClient::get_password_policies`](crate::PassboltClient) for instance.
#[uniffi::export]
pub fn generate_secret(policies: PasswordPolicies) -> Result<String, PassboltError> {
    Ok(generator::generate_secret(&policies.into())?)
}

/// A PIN code of `length` digits, brought within 4 to 12.
#[uniffi::export(default(length = 4))]
#[must_use]
pub fn generate_pin_code(length: u32) -> String {
    generator::generate_pin_code(length)
}

/// The entropy of `secret` in bits, measured as the extension does: as a passphrase when it
/// is words of the list joined by one separator.
#[uniffi::export]
#[must_use]
pub fn secret_entropy(secret: String) -> f64 {
    generator::secret_entropy(&secret)
}

/// The strength the extension shows for `secret`.
#[uniffi::export]
#[must_use]
pub fn secret_strength(secret: String) -> Strength {
    generator::Strength::of(generator::secret_entropy(&secret)).into()
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[test]
    fn test_the_default_policies_generate_18_characters() {
        let password = generate_secret(default_password_policies()).unwrap();

        assert_eq!(password.chars().count(), 18);
        assert_eq!(secret_strength(password), Strength::Strong);
    }

    #[test]
    fn test_a_passphrase_without_case_is_lowercase() {
        let settings = PassphraseGeneratorSettings {
            words: 5,
            word_separator: "-".into(),
            word_case: None,
            min_words: 4,
            max_words: 40,
        };

        let passphrase = generate_passphrase(settings).unwrap();

        assert_eq!(passphrase, passphrase.to_lowercase());
    }

    #[test]
    fn test_settings_that_cannot_generate_are_an_invalid_argument() {
        let mut policies = default_password_policies();
        policies.password_generator_settings.length = 4;

        let error = generate_secret(policies).unwrap_err();

        assert!(
            matches!(error, PassboltError::InvalidArgument { .. }),
            "{error}"
        );
    }

    #[rstest]
    #[case::short(2, 4)]
    #[case::six(6, 6)]
    fn test_a_pin_code_has_the_length_asked_within_bounds(
        #[case] length: u32,
        #[case] expected: usize,
    ) {
        assert_eq!(generate_pin_code(length).len(), expected);
    }

    #[test]
    fn test_the_policies_keep_their_fields_through_the_ffi() {
        let mut policies = default_password_policies();
        policies.default_generator = GeneratorType::Passphrase;
        policies.passphrase_generator_settings.word_case = Some(WordCase::Camelcase);

        let back = PasswordPolicies::from(generator::PasswordPolicies::from(policies));

        assert!(matches!(back.default_generator, GeneratorType::Passphrase));
        assert!(matches!(
            back.passphrase_generator_settings.word_case,
            Some(WordCase::Camelcase)
        ));
    }
}
