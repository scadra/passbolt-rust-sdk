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

use passbolt_sdk::{AuthError, PassboltError, PassboltSdk, SdkConfig};
use serde_json::Value;

use crate::common::*;

async fn login_error(fake: &FakePassbolt, config: &SdkConfig) -> PassboltError {
    match PassboltSdk::login(fake.clone(), config, None, 3).await {
        Ok(_) => panic!("login succeeded"),
        Err(error) => error,
    }
}

#[tokio::test]
async fn login_answers_the_gpgauth_challenge() {
    let fake = FakePassbolt::new();

    login_ada(&fake).await;

    let login_requests = fake.requests_to("POST", "/auth/login.json");
    assert_eq!(login_requests.len(), 2);
    assert_eq!(
        login_requests[0].json_body()["gpg_auth"]["keyid"],
        ADA.fingerprint()
    );
    let user_token_result = login_requests[1].json_body()["gpg_auth"]["user_token_result"]
        .as_str()
        .unwrap();
    assert!(
        user_token_result.starts_with("gpgauthv1.3.0|36|"),
        "{user_token_result}"
    );
}

#[tokio::test]
async fn login_keeps_the_csrf_cookie_and_the_user_id() {
    let fake = FakePassbolt::new();

    let client = login_ada(&fake).await;

    assert_eq!(client.csrf_token(), CSRF_TOKEN);
    assert_eq!(client.user_id, ADA_ID);
}

#[tokio::test]
async fn login_rejects_an_empty_server_url() {
    let mut config = ada_config();
    config.server_url = String::new();

    let error = login_error(&FakePassbolt::new(), &config).await;

    assert!(matches!(error, PassboltError::Config(_)), "{error:?}");
}

#[tokio::test]
async fn login_rejects_an_invalid_private_key() {
    let mut config = ada_config();
    config.private_key_armored = "not a key".into();

    let error = login_error(&FakePassbolt::new(), &config).await;

    assert!(matches!(error, PassboltError::Crypto(_)), "{error:?}");
}

#[tokio::test]
async fn login_stops_after_the_challenge_with_a_wrong_passphrase() {
    let fake = FakePassbolt::new();
    let mut config = ada_config();
    config.passphrase = "wrong".to_string().into();

    let error = login_error(&fake, &config).await;

    assert!(
        matches!(error, PassboltError::Auth(AuthError::LoginFailed(_))),
        "{error:?}"
    );
    assert_eq!(fake.requests_to("POST", "/auth/login.json").len(), 1);
}

#[tokio::test]
async fn login_reports_an_unknown_key() {
    let mut config = ada_config();
    config.private_key_armored = BETTY.private.into();
    config.passphrase = BETTY.passphrase.to_string().into();

    let error = login_error(&FakePassbolt::new(), &config).await;

    let PassboltError::Auth(AuthError::LoginFailed(message)) = error else {
        panic!("{error:?}")
    };
    assert!(
        message.contains("400") && message.contains("no user associated"),
        "{message}"
    );
}

#[tokio::test]
async fn logout_sends_the_csrf_token() {
    let fake = FakePassbolt::new();
    let client = login_ada(&fake).await;

    client.logout().await.unwrap();

    let logout_requests = fake.requests_to("POST", "/auth/logout.json");
    assert_eq!(logout_requests[0].header("X-CSRF-Token"), Some(CSRF_TOKEN));
}

#[tokio::test]
async fn logout_returns_the_refusal_of_the_server() {
    let fake = FakePassbolt::new();
    let client = login_ada(&fake).await;
    fake.on_error_saying(
        "POST",
        "/auth/logout.json",
        403,
        "CSRF token from either the request body or request headers did not match or is missing.",
    );

    let error = client.logout().await.unwrap_err();

    assert!(
        matches!(&error, PassboltError::Api(api_error) if api_error.status == 403),
        "{error:?}"
    );
    assert!(error.to_string().contains("CSRF token"), "{error}");
}

#[tokio::test]
async fn writes_send_the_latest_csrf_cookie() {
    let fake = FakePassbolt::new();
    fake.on(
        "GET",
        &resource_path(),
        data::resource_v4("password-string", "p"),
    );
    fake.on("DELETE", &resource_path(), Value::Null);
    let client = login_ada(&fake).await;
    fake.rotate_csrf_token("rotated-token");

    client.get_resource(RESOURCE_ID).await.unwrap();
    client.delete_resource(RESOURCE_ID).await.unwrap();

    let delete = &fake.requests_to("DELETE", &resource_path())[0];
    assert_eq!(delete.header("X-CSRF-Token"), Some("rotated-token"));
}

#[tokio::test]
async fn login_rejects_a_server_holding_another_public_key() {
    let fake = FakePassbolt::new();
    fake.on("GET", "/users/me.json", data::user_with_key("ada", &BETTY));

    let error = login_error(&fake, &ada_config()).await;

    assert!(
        matches!(error, PassboltError::Auth(AuthError::KeyCrossCheckFailed)),
        "{error:?}"
    );
}

#[tokio::test]
async fn login_refuses_to_send_back_a_non_token_challenge() {
    let fake = FakePassbolt::new();
    fake.send_challenge("any plaintext the server wants decrypted");

    let error = login_error(&fake, &ada_config()).await;

    assert!(
        matches!(error, PassboltError::Auth(AuthError::LoginFailed(_))),
        "{error:?}"
    );
    assert_eq!(fake.requests_to("POST", "/auth/login.json").len(), 1);
}

#[tokio::test]
async fn login_rejects_a_session_without_csrf_token() {
    let fake = FakePassbolt::new();
    fake.without_csrf_cookie();

    let error = login_error(&fake, &ada_config()).await;

    assert!(
        matches!(error, PassboltError::Auth(AuthError::LoginFailed(_))),
        "{error:?}"
    );
}
