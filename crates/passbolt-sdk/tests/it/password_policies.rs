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

use passbolt_sdk::generator::{
    detect_passphrase, generate_secret, GeneratorType, PassphraseGeneratorSettings,
    PasswordPolicies, WordCase,
};
use serde_json::json;

use crate::common::*;

const POLICIES: &str = "/password-policies/settings.json";
const LEGACY_SETTINGS: &str = "/password-generator/settings.json";

#[tokio::test]
async fn the_password_policies_of_the_organization_are_read() {
    let fake = FakePassbolt::new();
    fake.on("GET", POLICIES, data::password_policies());
    let client = login_ada(&fake).await;

    let policies = client.get_password_policies().await.unwrap();

    assert_eq!(policies.default_generator, GeneratorType::Passphrase);
    assert_eq!(policies.passphrase_generator_settings.words, 6);
    assert_eq!(
        policies.passphrase_generator_settings.word_case,
        WordCase::Camelcase
    );
    assert_eq!(policies.password_generator_settings.length, 24);
    assert!(!policies.external_dictionary_check);
}

#[tokio::test]
async fn a_secret_follows_the_policies_of_the_organization() {
    let fake = FakePassbolt::new();
    fake.on("GET", POLICIES, data::password_policies());
    let client = login_ada(&fake).await;
    let policies = client.get_password_policies().await.unwrap();

    let secret = generate_secret(&policies).unwrap();

    // Counted as the extension does: a word may hold a hyphen (`t-shirt`).
    let passphrase = detect_passphrase(&secret).unwrap();
    assert_eq!(
        (passphrase.words, passphrase.separator.as_str()),
        (6, "-"),
        "{secret}"
    );
}

#[tokio::test]
async fn a_server_before_4_2_gives_its_legacy_generator_settings() {
    let fake = FakePassbolt::new();
    fake.on_error("GET", POLICIES, 404);
    fake.on(
        "GET",
        LEGACY_SETTINGS,
        json!({"default_generator": "passphrase"}),
    );
    let client = login_ada(&fake).await;

    let policies = client.get_password_policies().await.unwrap();

    assert_eq!(policies.default_generator, GeneratorType::Passphrase);
    assert_eq!(policies.passphrase_generator_settings.words, 9);
}

#[tokio::test]
async fn the_password_policies_are_saved_by_an_administrator() {
    let fake = FakePassbolt::new();
    fake.on("POST", POLICIES, data::password_policies());
    let client = login_ada(&fake).await;
    let policies = PasswordPolicies {
        default_generator: GeneratorType::Passphrase,
        passphrase_generator_settings: PassphraseGeneratorSettings {
            words: 6,
            ..PassphraseGeneratorSettings::default()
        },
        ..PasswordPolicies::default()
    };

    let saved = client.save_password_policies(&policies).await.unwrap();

    let body = fake.body_of("POST", POLICIES);
    assert_eq!(body["default_generator"], "passphrase");
    assert_eq!(body["passphrase_generator_settings"]["words"], 6);
    assert_eq!(body["password_generator_settings"]["length"], 18);
    assert_eq!(saved.source.as_deref(), Some("db"));
}
