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

use passbolt_sdk::{AuthError, PassboltError, PassboltSdk};
use rstest::rstest;
use serde_json::json;

use crate::common::*;

async fn login_error(fake: &FakePassbolt) -> PassboltError {
    match PassboltSdk::login(fake.clone(), &ada_config(), None, 3).await {
        Ok(_) => panic!("login succeeded"),
        Err(error) => error,
    }
}

#[tokio::test]
async fn login_fails_without_the_challenge_header() {
    let fake = FakePassbolt::new();
    fake.without_auth_token_header();

    let error = login_error(&fake).await;

    let PassboltError::Auth(AuthError::LoginFailed(message)) = error else {
        panic!("{error:?}")
    };
    assert!(message.contains("X-GPGAuth-User-Auth-Token"), "{message}");
    assert_eq!(fake.requests_to("POST", "/auth/login.json").len(), 1);
}

#[rstest]
#[case::server_error(500, "Internal error.")]
#[case::authentication_failed(400, "The authentication failed.")]
#[tokio::test]
async fn login_reports_a_refused_verification(#[case] status: u16, #[case] server_message: &str) {
    let fake = FakePassbolt::new();
    fake.fail_login_verification(status, server_message);

    let error = login_error(&fake).await;

    let PassboltError::Auth(AuthError::LoginFailed(message)) = error else {
        panic!("{error:?}")
    };
    assert!(
        message.contains(&status.to_string()) && message.contains(server_message),
        "{message}"
    );
}

#[tokio::test]
async fn auth_status_is_true_for_a_live_session() {
    let fake = FakePassbolt::new();
    fake.on("GET", "/auth/is-authenticated.json", json!(null));
    let client = login_ada(&fake).await;

    assert!(client.check_auth_status().await.unwrap());
}

#[tokio::test]
async fn auth_status_is_false_for_an_expired_session() {
    let fake = FakePassbolt::new();
    fake.on_error("GET", "/auth/is-authenticated.json", 401);
    let client = login_ada(&fake).await;

    assert!(!client.check_auth_status().await.unwrap());
}

#[tokio::test]
async fn an_answer_without_gpgauth_headers_is_refused() {
    let fake = FakePassbolt::new();
    fake.without_gpgauth_headers();

    let error = PassboltSdk::login(fake.clone(), &ada_config(), None, 1)
        .await
        .err()
        .unwrap();

    assert!(
        error
            .to_string()
            .contains("GPGAuth: version none is not supported"),
        "{error}"
    );
    assert_eq!(
        fake.requests_to("POST", "/auth/login.json").len(),
        1,
        "no stage 2"
    );
}

#[tokio::test]
async fn an_identity_check_answered_without_gpgauth_headers_is_refused_before_login() {
    let fake = FakePassbolt::new();
    fake.without_gpgauth_headers();
    let mut config = ada_config();
    config.server_public_key = SERVER.public.into();

    let error = PassboltSdk::login(fake.clone(), &config, None, 1)
        .await
        .err()
        .unwrap();

    assert!(matches!(error, PassboltError::Auth(_)), "{error:?}");
    assert!(fake.requests_to("POST", "/auth/login.json").is_empty());
}
