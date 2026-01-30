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

//! `NativeHttpClient` (reqwest) against wiremock servers.

use passbolt_sdk::{HttpClient, NativeHttpClient, NativeHttpConfig};
use wiremock::matchers::{any, body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn native_client() -> NativeHttpClient {
    NativeHttpClient::new(&NativeHttpConfig {
        tls_skip_verify: false,
        client_cert_pem: None,
        client_key_pem: None,
        proxy_url: None,
        resolve: Vec::new(),
        timeout: None,
    })
    .unwrap()
}

fn server_url(server: &MockServer, path: &str) -> String {
    format!("{}{path}", server.uri())
}

#[tokio::test]
async fn sends_json_headers_custom_headers_and_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/resources.json"))
        .and(header("Accept", "application/json"))
        .and(header("Content-Type", "application/json"))
        .and(header("X-CSRF-Token", "csrf"))
        .and(body_json(serde_json::json!({ "name": "GitHub" })))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("X-Test", "yes")
                .set_body_string("{}"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let response = native_client()
        .post(
            &server_url(&server, "/resources.json"),
            &[("X-CSRF-Token", "csrf")],
            br#"{"name":"GitHub"}"#,
        )
        .await
        .unwrap();

    assert_eq!(response.status, 201);
    assert_eq!(response.header("x-test"), Some("yes"));
    assert_eq!(response.body, b"{}");
}

#[tokio::test]
async fn keeps_the_session_cookie_between_requests() {
    let server = MockServer::start().await;
    Mock::given(path("/auth/login.json"))
        .respond_with(
            ResponseTemplate::new(200).insert_header("Set-Cookie", "passbolt_session=abc; Path=/"),
        )
        .mount(&server)
        .await;
    Mock::given(path("/users/me.json"))
        .and(header("Cookie", "passbolt_session=abc"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let client = native_client();

    client
        .post(&server_url(&server, "/auth/login.json"), &[], b"{}")
        .await
        .unwrap();
    let me_response = client
        .get(&server_url(&server, "/users/me.json"), &[])
        .await
        .unwrap();

    assert_eq!(me_response.status, 200);
}

#[tokio::test]
async fn exposes_the_csrf_cookie() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(
            ResponseTemplate::new(200).insert_header("Set-Cookie", "csrfToken=t0k3n; Path=/"),
        )
        .mount(&server)
        .await;

    let response = native_client()
        .post(&server_url(&server, "/auth/login.json"), &[], b"{}")
        .await
        .unwrap();

    assert!(
        response
            .headers_by_name("set-cookie-name")
            .contains(&"csrfToken=t0k3n"),
        "{:?}",
        response.headers
    );
}

#[tokio::test]
async fn follows_redirects_on_the_same_host() {
    let server = MockServer::start().await;
    Mock::given(path("/users/me.json"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("Location", "/mfa/verify/error.json"),
        )
        .mount(&server)
        .await;
    Mock::given(path("/mfa/verify/error.json"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;

    let response = native_client()
        .get(&server_url(&server, "/users/me.json"), &[])
        .await
        .unwrap();

    assert_eq!(
        response.status, 403,
        "MFA detection relies on this redirect"
    );
}

#[tokio::test]
async fn http_errors_are_responses() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let response = native_client()
        .get(&server_url(&server, "/anything.json"), &[])
        .await
        .unwrap();

    assert_eq!(response.status, 500);
}

#[tokio::test]
async fn an_unreachable_server_is_a_transport_error() {
    assert!(native_client()
        .get("http://127.0.0.1:1/users/me.json", &[])
        .await
        .is_err());
}

#[tokio::test]
async fn does_not_follow_redirects_to_another_origin() {
    let passbolt_server = MockServer::start().await;
    let other_server = MockServer::start().await;
    Mock::given(any())
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("Location", server_url(&other_server, "/elsewhere")),
        )
        .mount(&passbolt_server)
        .await;

    let response = native_client()
        .post(
            &server_url(&passbolt_server, "/auth/login.json"),
            &[("X-CSRF-Token", "csrf")],
            br#"{"gpg_auth":{}}"#,
        )
        .await;

    assert!(
        other_server.received_requests().await.unwrap().is_empty(),
        "request leaked to {}",
        other_server.uri()
    );
    assert!(response.is_err());
}

#[tokio::test]
async fn reads_a_cookie_set_by_any_earlier_response() {
    let server = MockServer::start().await;
    Mock::given(path("/auth/verify.json"))
        .respond_with(
            ResponseTemplate::new(200).insert_header("Set-Cookie", "csrfToken=t0k3n; Path=/"),
        )
        .mount(&server)
        .await;
    let http = native_client();

    http.get(&server_url(&server, "/auth/verify.json"), &[])
        .await
        .unwrap();

    assert_eq!(
        http.cookie(&server.uri(), "csrfToken").as_deref(),
        Some("t0k3n")
    );
}

#[tokio::test]
async fn says_it_is_the_rust_client() {
    let server = MockServer::start().await;
    Mock::given(header(
        "User-Agent",
        concat!("passbolt-rust/", env!("CARGO_PKG_VERSION")),
    ))
    .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
    .expect(1)
    .mount(&server)
    .await;

    let response = native_client()
        .get(&server_url(&server, "/healthcheck/status.json"), &[])
        .await
        .unwrap();

    assert_eq!(response.status, 200);
}
