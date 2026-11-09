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

//! `passbolt generate`: a password, passphrase or PIN code as the browser extension generates
//! it, from the password policies of the organization.

use anyhow::{bail, Result};
use clap::{Args, Subcommand, ValueEnum};
use passbolt_sdk::generator::{
    generate_passphrase, generate_password, generate_pin_code, secret_entropy, GeneratorType,
    PasswordGeneratorSettings, PasswordPolicies, Strength, WordCase,
};
use serde_json::json;

use crate::util::output;

#[derive(Args, Debug)]
pub struct GenerateArgs {
    /// What to generate; default: the default generator of the organization
    #[command(subcommand)]
    pub kind: Option<GenerateKind>,
    /// Use the default policies of Passbolt, without logging in
    #[arg(long, global = true)]
    pub offline: bool,
}

#[derive(Subcommand, Debug)]
pub enum GenerateKind {
    /// A password drawn from character sets
    Password(PasswordArgs),
    /// A passphrase of words of the EFF list
    Passphrase(PassphraseArgs),
    /// A PIN code
    Pin {
        /// Number of digits, 4 to 12
        #[arg(short = 'l', long, default_value_t = 4)]
        length: u32,
    },
}

#[derive(Args, Debug, Default)]
pub struct PasswordArgs {
    /// Number of characters; default: the organization's
    #[arg(short = 'l', long)]
    pub length: Option<u32>,
    /// Character sets to draw from, replacing the organization's; repeat or separate with commas
    #[arg(long, value_enum, value_delimiter = ',')]
    pub charset: Vec<Charset>,
    /// Keep the look-alike characters `O l | I 0 1`
    #[arg(long)]
    pub include_look_alike: bool,
}

#[derive(Args, Debug, Default)]
pub struct PassphraseArgs {
    /// Number of words, 4 to 40; default: the organization's
    #[arg(short = 'w', long)]
    pub words: Option<u32>,
    /// Text between the words; default: the organization's
    #[arg(short = 's', long)]
    pub separator: Option<String>,
    /// Case of the words; default: the organization's
    #[arg(long, value_enum)]
    pub case: Option<Case>,
}

/// The character sets of the extension.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Charset {
    /// A-Z
    Upper,
    /// a-z
    Lower,
    /// 0-9
    Digit,
    /// { [ ( | ) ] }
    Parenthesis,
    /// # $ % & @ ^ ~
    Char1,
    /// . , : ;
    Char2,
    /// ' " and the backtick
    Char3,
    /// / \ _ -
    Char4,
    /// < * + ! ? =
    Char5,
    /// The emoticons of Unicode 6
    Emoji,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Case {
    Lowercase,
    Uppercase,
    Camelcase,
}

impl From<Case> for WordCase {
    fn from(case: Case) -> Self {
        match case {
            Case::Lowercase => Self::Lowercase,
            Case::Uppercase => Self::Uppercase,
            Case::Camelcase => Self::Camelcase,
        }
    }
}

/// The password settings of `policies` with the options given instead.
fn password_settings(
    policies: &PasswordPolicies,
    args: &PasswordArgs,
) -> PasswordGeneratorSettings {
    let mut settings = policies.password_generator_settings.clone();
    if let Some(length) = args.length {
        settings.length = length;
    }
    if !args.charset.is_empty() {
        let has = |charset| args.charset.contains(&charset);
        settings.mask_upper = has(Charset::Upper);
        settings.mask_lower = has(Charset::Lower);
        settings.mask_digit = has(Charset::Digit);
        settings.mask_parenthesis = has(Charset::Parenthesis);
        settings.mask_char1 = has(Charset::Char1);
        settings.mask_char2 = has(Charset::Char2);
        settings.mask_char3 = has(Charset::Char3);
        settings.mask_char4 = has(Charset::Char4);
        settings.mask_char5 = has(Charset::Char5);
        settings.mask_emoji = has(Charset::Emoji);
    }
    if args.include_look_alike {
        settings.exclude_look_alike_chars = false;
    }
    settings
}

/// The secret `args` ask for, from `policies`.
pub fn generate(args: &GenerateArgs, policies: &PasswordPolicies) -> Result<String> {
    let kind = args.kind.as_ref();
    let secret = match kind {
        Some(GenerateKind::Pin { length }) => {
            if !(4..=12).contains(length) {
                bail!("a PIN code has 4 to 12 digits, not {length}");
            }
            generate_pin_code(*length)
        }
        Some(GenerateKind::Password(password)) => {
            generate_password(&password_settings(policies, password))?
        }
        Some(GenerateKind::Passphrase(passphrase)) => {
            let mut settings = policies.passphrase_generator_settings.clone();
            if let Some(words) = passphrase.words {
                settings.words = words;
            }
            if let Some(separator) = &passphrase.separator {
                settings.word_separator.clone_from(separator);
            }
            if let Some(case) = passphrase.case {
                settings.word_case = case.into();
            }
            generate_passphrase(&settings)?
        }
        None => match policies.default_generator {
            GeneratorType::Password => {
                generate_password(&password_settings(policies, &PasswordArgs::default()))?
            }
            GeneratorType::Passphrase => {
                generate_passphrase(&policies.passphrase_generator_settings)?
            }
        },
    };
    Ok(secret)
}

/// The secret alone on stdout, for a script; with `-j`, its entropy and strength too.
pub fn print(secret: &str, json_output: bool) -> Result<()> {
    if json_output {
        let entropy = secret_entropy(secret);
        let strength = Strength::of(entropy);
        return output::print_json(&json!({
            "secret": secret,
            "entropy": (entropy * 100.0).round() / 100.0,
            "strength": strength,
        }));
    }
    println!("{secret}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    fn args(kind: Option<GenerateKind>) -> GenerateArgs {
        GenerateArgs {
            kind,
            offline: false,
        }
    }

    #[test]
    fn test_without_a_kind_the_default_generator_of_the_organization_applies() {
        let policies = PasswordPolicies {
            default_generator: GeneratorType::Passphrase,
            ..PasswordPolicies::default()
        };

        let secret = generate(&args(None), &policies).unwrap();

        assert_eq!(secret.split(' ').count(), 9, "{secret}");
    }

    #[test]
    fn test_the_charsets_given_replace_those_of_the_organization() {
        let password = PasswordArgs {
            length: Some(40),
            charset: vec![Charset::Digit],
            include_look_alike: true,
        };

        let secret = generate(
            &args(Some(GenerateKind::Password(password))),
            &PasswordPolicies::default(),
        )
        .unwrap();

        assert_eq!(secret.len(), 40);
        assert!(
            secret.bytes().all(|digit| digit.is_ascii_digit()),
            "{secret}"
        );
    }

    #[test]
    fn test_the_passphrase_options_override_the_organization() {
        let passphrase = PassphraseArgs {
            words: Some(5),
            separator: Some("_".into()),
            case: Some(Case::Uppercase),
        };

        let secret = generate(
            &args(Some(GenerateKind::Passphrase(passphrase))),
            &PasswordPolicies::default(),
        )
        .unwrap();

        assert_eq!(secret.split('_').count(), 5, "{secret}");
        assert_eq!(secret, secret.to_uppercase());
    }

    #[rstest]
    #[case::too_short(3)]
    #[case::too_long(13)]
    fn test_a_pin_code_out_of_bounds_is_refused(#[case] length: u32) {
        let error = generate(
            &args(Some(GenerateKind::Pin { length })),
            &PasswordPolicies::default(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("4 to 12"), "{error}");
    }
}
