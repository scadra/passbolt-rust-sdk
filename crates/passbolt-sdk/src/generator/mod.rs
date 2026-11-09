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
//! from the password policies of the organization, and their strength measured as it does.
//!
//! ```
//! use passbolt_sdk::generator::{generate_secret, secret_entropy, PasswordPolicies, Strength};
//!
//! // Without a session, the defaults of the server: 18 characters, about 116 bits.
//! let password = generate_secret(&PasswordPolicies::default()).unwrap();
//! assert_eq!(Strength::of(secret_entropy(&password)), Strength::Strong);
//! ```
//!
//! With a session, [`PassboltSdk::get_password_policies`](crate::PassboltSdk::get_password_policies)
//! reads the policies of the organization.

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
use serde::{Deserialize, Serialize};

use crate::error::PassboltError;

/// What the generator makes by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GeneratorType {
    #[default]
    Password,
    Passphrase,
}

/// The password policies of the organization, `/password-policies/settings.json`.
///
/// Which generator applies by default and the settings of each. Fields the server leaves out
/// keep the defaults of the extension, an unknown generator is `password`, as it does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PasswordPolicies {
    #[serde(deserialize_with = "generator_type")]
    pub default_generator: GeneratorType,
    /// Check new passwords against Have I Been Pwned.
    pub external_dictionary_check: bool,
    pub password_generator_settings: PasswordGeneratorSettings,
    pub passphrase_generator_settings: PassphraseGeneratorSettings,
    /// Where the server read them: `default`, `file`, `env`, `db`…
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Set once an administrator saved them (Passbolt Pro).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_by: Option<String>,
}

impl Default for PasswordPolicies {
    fn default() -> Self {
        Self {
            default_generator: GeneratorType::Password,
            external_dictionary_check: true,
            password_generator_settings: PasswordGeneratorSettings::default(),
            passphrase_generator_settings: PassphraseGeneratorSettings::default(),
            source: None,
            id: None,
            created: None,
            created_by: None,
            modified: None,
            modified_by: None,
        }
    }
}

fn generator_type<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<GeneratorType, D::Error> {
    let name = Option::<String>::deserialize(deserializer)?;
    Ok(if name.as_deref() == Some("passphrase") {
        GeneratorType::Passphrase
    } else {
        GeneratorType::Password
    })
}

/// A secret from the default generator of `policies`, with its settings.
///
/// # Errors
/// `InvalidArgument` when its settings cannot generate one (no character set, a length or a
/// number of words out of bounds).
pub fn generate_secret(policies: &PasswordPolicies) -> Result<String, PassboltError> {
    match policies.default_generator {
        GeneratorType::Password => generate_password(&policies.password_generator_settings),
        GeneratorType::Passphrase => generate_passphrase(&policies.passphrase_generator_settings),
    }
}

/// An index under `len`, uniform, from the operating system's generator (the Web Crypto API
/// in a browser).
pub(crate) fn random_index(len: usize) -> usize {
    rand::rngs::OsRng.gen_range(0..len)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use serde_json::json;

    use super::*;

    #[test]
    fn test_the_policies_of_a_server_without_settings_are_the_defaults() {
        // The answer of a server with the defaults, from PasswordPoliciesSettingsDto.
        let policies: PasswordPolicies = serde_json::from_value(json!({
            "default_generator": "password",
            "password_generator_settings": {
                "length": 18, "mask_upper": true, "mask_lower": true, "mask_digit": true,
                "mask_parenthesis": true, "mask_emoji": false, "mask_char1": true,
                "mask_char2": true, "mask_char3": true, "mask_char4": true, "mask_char5": true,
                "exclude_look_alike_chars": true
            },
            "passphrase_generator_settings": {
                "words": 9, "word_separator": " ", "word_case": "lowercase"
            },
            "source": "default",
            "external_dictionary_check": true
        }))
        .unwrap();

        assert_eq!(
            policies,
            PasswordPolicies {
                source: Some("default".into()),
                ..PasswordPolicies::default()
            }
        );
    }

    #[rstest]
    #[case::passphrase(json!("passphrase"), GeneratorType::Passphrase)]
    #[case::password(json!("password"), GeneratorType::Password)]
    #[case::unknown(json!("diceware"), GeneratorType::Password)]
    #[case::null(json!(null), GeneratorType::Password)]
    fn test_an_unknown_generator_is_the_password_one(
        #[case] name: serde_json::Value,
        #[case] expected: GeneratorType,
    ) {
        let policies: PasswordPolicies =
            serde_json::from_value(json!({ "default_generator": name })).unwrap();

        assert_eq!(policies.default_generator, expected);
    }

    #[test]
    fn test_the_legacy_settings_give_the_generator_only() {
        // `/password-generator/settings.json` of a server before 4.2.
        let policies: PasswordPolicies =
            serde_json::from_value(json!({ "default_generator": "passphrase" })).unwrap();

        assert_eq!(policies.default_generator, GeneratorType::Passphrase);
        assert_eq!(policies.passphrase_generator_settings.words, 9);
    }

    #[test]
    fn test_the_secret_comes_from_the_default_generator() {
        let policies = PasswordPolicies {
            default_generator: GeneratorType::Passphrase,
            ..PasswordPolicies::default()
        };

        let secret = generate_secret(&policies).unwrap();

        assert_eq!(secret.split(' ').count(), 9, "{secret}");
    }

    #[test]
    fn test_saved_policies_are_sent_without_the_fields_the_server_sets() {
        let body = serde_json::to_value(PasswordPolicies::default()).unwrap();

        assert!(body.get("source").is_none());
        assert!(body.get("id").is_none());
        assert_eq!(body["default_generator"], "password");
        assert_eq!(
            body["passphrase_generator_settings"]["word_case"],
            "lowercase"
        );
    }
}
