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

use passbolt_sdk::{auth, AuthError, PassboltError, PassboltSdk, SdkConfig};

use crate::common::*;

const VERIFY_PATH: &str = "/auth/verify.json";

fn pinning_the_server_key() -> SdkConfig {
    let mut config = ada_config();
    config.server_public_key = SERVER.public.into();
    config
}

async fn login_error(fake: &FakePassbolt, config: &SdkConfig) -> PassboltError {
    match PassboltSdk::login(fake.clone(), config, None, 3).await {
        Ok(_) => panic!("login succeeded"),
        Err(error) => error,
    }
}

fn assert_refused_before_login(fake: &FakePassbolt, error: &PassboltError, reason: &str) {
    assert!(
        matches!(error, PassboltError::Auth(AuthError::ServerIdentityMismatch(message)) if message.contains(reason)),
        "{error:?}"
    );
    assert!(fake.requests_to("POST", "/auth/login.json").is_empty());
}

fn sent_tokens(fake: &FakePassbolt) -> Vec<String> {
    fake.requests_to("POST", VERIFY_PATH)
        .iter()
        .map(|request| {
            SERVER.decrypt(
                request.json_body()["gpg_auth"]["server_verify_token"]
                    .as_str()
                    .unwrap(),
            )
        })
        .collect()
}

#[tokio::test]
async fn without_a_pinned_server_nothing_is_verified() {
    let fake = FakePassbolt::new();

    login_ada(&fake).await;

    assert!(fake.requests_to("POST", VERIFY_PATH).is_empty());
}

#[tokio::test]
async fn the_server_proves_its_key_with_a_fresh_token_at_each_login() {
    let fake = FakePassbolt::new();

    for _ in 0..2 {
        PassboltSdk::login(fake.clone(), &pinning_the_server_key(), None, 3)
            .await
            .unwrap();
    }

    let tokens = sent_tokens(&fake);
    assert_eq!(tokens.len(), 2);
    assert_ne!(tokens[0], tokens[1], "a token is never sent twice");
    assert!(tokens
        .iter()
        .all(|token| token.starts_with("gpgauthv1.3.0|36|")));
}

#[tokio::test]
async fn a_server_without_the_private_key_is_refused_before_login() {
    let fake = FakePassbolt::new();
    fake.impersonated_with(&BETTY);

    let error = login_error(&fake, &pinning_the_server_key()).await;

    assert_refused_before_login(&fake, &error, "could not prove");
}

#[tokio::test]
async fn go_passbolt_cli_stored_tokens_are_sent_again() {
    let fake = FakePassbolt::new();
    let token = auth::new_verify_token();
    let mut config = ada_config();
    config.server_verify_token.clone_from(&token);
    config.server_verify_enc_token = SERVER.encrypt(&token);

    PassboltSdk::login(fake.clone(), &config, None, 3)
        .await
        .unwrap();

    assert_eq!(sent_tokens(&fake), [token]);
}

#[tokio::test]
async fn go_passbolt_cli_stored_tokens_do_not_fool_the_check_on_an_impostor() {
    let fake = FakePassbolt::new();
    fake.impersonated_with(&BETTY);
    let token = auth::new_verify_token();
    let mut config = ada_config();
    config.server_verify_token.clone_from(&token);
    config.server_verify_enc_token = SERVER.encrypt(&token);

    let error = login_error(&fake, &config).await;

    assert_refused_before_login(&fake, &error, "could not prove");
}

#[tokio::test]
async fn an_incomplete_stored_verification_asks_to_verify_again() {
    let fake = FakePassbolt::new();
    let mut config = ada_config();
    // What `passbolt verify` used to store: the fingerprint, no token.
    config.server_verify_enc_token = SERVER.fingerprint();

    let error = login_error(&fake, &config).await;

    assert_refused_before_login(&fake, &error, "passbolt verify");
}

#[tokio::test]
async fn the_server_key_is_fetched_with_its_fingerprint() {
    let fake = FakePassbolt::new();

    let (fingerprint, armored_key) = auth::fetch_server_key(&fake, BASE_URL).await.unwrap();

    assert_eq!(fingerprint, SERVER.fingerprint());
    assert_eq!(armored_key, SERVER.public);
}

#[tokio::test]
async fn a_server_key_announced_with_another_fingerprint_is_refused() {
    let fake = FakePassbolt::new();
    let mut verify = data::auth_verify(&SERVER);
    verify["fingerprint"] = ADA.fingerprint().into();
    fake.on("GET", "/auth/verify.json", verify);

    let error = auth::fetch_server_key(&fake, BASE_URL).await.unwrap_err();

    assert!(
        matches!(
            error,
            PassboltError::Auth(AuthError::ServerIdentityMismatch(_))
        ),
        "{error:?}"
    );
}
