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

//! `PassboltClient` against a wiremock server answering the `GPGAuth` login as Passbolt does.

use std::sync::Arc;

use passbolt_ffi::{fetch_server_key, FfiLoginOptions, PassboltClient, PassboltFfiError};
use passbolt_sdk::crypto;
use serde_json::{json, Value};
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const ADA_PRIVATE: &str = include_str!("../../passbolt-sdk/tests/fixtures/keys/ada_private.asc");
const ADA_PUBLIC: &str = include_str!("../../passbolt-sdk/tests/fixtures/keys/ada_public.asc");
const ADA_PASSPHRASE: &str = "ada-passphrase";
const SERVER_PRIVATE: &str =
    include_str!("../../passbolt-sdk/tests/fixtures/keys/server_private.asc");
const SERVER_PUBLIC: &str =
    include_str!("../../passbolt-sdk/tests/fixtures/keys/server_public.asc");
const BETTY_PUBLIC: &str = include_str!("../../passbolt-sdk/tests/fixtures/keys/betty_public.asc");
const METADATA_PUBLIC: &str =
    include_str!("../../passbolt-sdk/tests/fixtures/keys/metadata_public.asc");
const METADATA_PRIVATE: &str =
    include_str!("../../passbolt-sdk/tests/fixtures/keys/metadata_private.asc");
const ADA_ID: &str = "8b6c3a10-0000-4000-8000-00000000a0da";
const RESOURCE_ID: &str = "7a5b2c30-0000-4000-8000-0000000000e1";
const PASSWORD_AND_DESCRIPTION_ID: &str = "a28a04cd-6f53-518a-967c-9963bf9cec51";
const BETTY_ID: &str = "8b6c3a10-0000-4000-8000-000000000be7";
const CAROL_ID: &str = "8b6c3a10-0000-4000-8000-0000000ca201";
const FOLDER_ID: &str = "5f6e7d8c-0000-4000-8000-0000000000f1";
const GROUP_ID: &str = "9c7d4b20-0000-4000-8000-000000000960";

const FOLDER: &str = include_str!("../../passbolt-sdk/tests/fixtures/data/folder.json");
const GROUP: &str = include_str!("../../passbolt-sdk/tests/fixtures/data/group.json");
const ROLES: &str = include_str!("../../passbolt-sdk/tests/fixtures/data/roles.json");
const USERS: &str = include_str!("../../passbolt-sdk/tests/fixtures/data/users.json");
const TAG: &str = include_str!("../../passbolt-sdk/tests/fixtures/data/tag.json");
const RESOURCE_TYPES: &str =
    include_str!("../../passbolt-sdk/tests/fixtures/data/resource_types.json");
const USER_DELETE_DRY_RUN_ERRORS: &str =
    include_str!("../../passbolt-sdk/tests/fixtures/data/user_delete_dry_run_errors.json");

/// A wiremock Passbolt and the runtime serving it: the client blocks on its own runtime.
struct Passbolt {
    runtime: tokio::runtime::Runtime,
    server: MockServer,
}

impl Passbolt {
    fn new() -> Self {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let server = runtime.block_on(MockServer::start());
        let passbolt = Self { runtime, server };
        passbolt.answer_login();
        passbolt
    }

    fn on(&self, http_method: &str, url_path: &str, body: &Value) {
        self.on_status(http_method, url_path, 200, body);
    }

    fn on_status(&self, http_method: &str, url_path: &str, status: u16, body: &Value) {
        let mock = Mock::given(method(http_method))
            .and(path(url_path))
            .respond_with(ResponseTemplate::new(status).set_body_json(envelope(body)));
        self.runtime.block_on(mock.mount(&self.server));
    }

    /// `GPGAuth` stage 1 then 2, and the CSRF cookie on the first GET.
    fn answer_login(&self) {
        let token = format!("gpgauthv1.3.0|36|{}|gpgauthv1.3.0", uuid::Uuid::new_v4());
        let ada_key = crypto::parse_public_key(ADA_PUBLIC).unwrap();
        let challenge = crypto::encrypt_message(token.as_bytes(), &[&ada_key]).unwrap();
        let stage_2 = Mock::given(method("POST"))
            .and(path("/auth/login.json"))
            .and(body_string_contains("user_token_result"))
            .respond_with(
                gpgauth(200, "true", "complete")
                    .insert_header("X-GPGAuth-Refer", "/")
                    .set_body_json(envelope(&json!({"user": {"id": ADA_ID}}))),
            )
            .with_priority(1);
        let stage_1 = Mock::given(method("POST"))
            .and(path("/auth/login.json"))
            .respond_with(
                gpgauth(200, "false", "stage1")
                    .insert_header(
                        "X-GPGAuth-User-Auth-Token",
                        php_quotemeta_urlencode(&challenge),
                    )
                    .set_body_json(envelope(&Value::Null)),
            )
            .with_priority(2);
        let me = Mock::given(method("GET"))
            .and(path("/users/me.json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Set-Cookie", "csrfToken=csrf-test-token; Path=/")
                    .set_body_json(envelope(&ada())),
            );
        for mock in [stage_2, stage_1, me] {
            self.runtime.block_on(mock.mount(&self.server));
        }
    }

    /// `GPGAuth` stage 0 as the server answers it: the key and the decrypted token.
    fn answer_server_verification(&self) {
        let key = Mock::given(method("GET"))
            .and(path("/auth/verify.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(envelope(&json!({
                "fingerprint": crypto::public_key_fingerprint(SERVER_PUBLIC).unwrap(),
                "keydata": SERVER_PUBLIC,
            }))));
        let token = Mock::given(method("POST"))
            .and(path("/auth/verify.json"))
            .respond_with(DecryptingServer);
        for mock in [key, token] {
            self.runtime.block_on(mock.mount(&self.server));
        }
    }

    fn login_with(
        &self,
        options: FfiLoginOptions,
    ) -> Result<Arc<PassboltClient>, PassboltFfiError> {
        PassboltClient::login_with_config(
            self.server.uri(),
            ADA_PRIVATE.into(),
            ADA_PASSPHRASE.into(),
            options,
        )
    }

    fn login(&self) -> Arc<PassboltClient> {
        PassboltClient::login(self.server.uri(), ADA_PRIVATE.into(), ADA_PASSPHRASE.into()).unwrap()
    }

    /// An error answer, as the server sends it: an `error` header and the failure in `body`.
    fn on_error(&self, http_method: &str, url_path: &str, status: u16, body: &Value) {
        let mock = Mock::given(method(http_method))
            .and(path(url_path))
            .respond_with(ResponseTemplate::new(status).set_body_json(json!({
                "header": {"status": "error", "message": "The operation failed."},
                "body": body
            })));
        self.runtime.block_on(mock.mount(&self.server));
    }

    fn received(&self, http_method: &str, url_path: &str) -> Vec<Request> {
        self.runtime
            .block_on(self.server.received_requests())
            .unwrap_or_default()
            .into_iter()
            .filter(|request| {
                request.method.as_str() == http_method && request.url.path() == url_path
            })
            .collect()
    }

    fn requests(&self, http_method: &str, url_path: &str) -> Vec<Value> {
        self.received(http_method, url_path)
            .into_iter()
            .map(|request| serde_json::from_slice(&request.body).unwrap_or(Value::Null))
            .collect()
    }

    fn queries(&self, http_method: &str, url_path: &str) -> Vec<String> {
        self.received(http_method, url_path)
            .into_iter()
            .map(|request| request.url.query().unwrap_or_default().to_string())
            .collect()
    }
}

/// The server's stage 0: decrypts the token with its private key and sends it back.
struct DecryptingServer;

impl Respond for DecryptingServer {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let server_key = crypto::parse_private_key(SERVER_PRIVATE).unwrap();
        let token = body
            .pointer("/gpg_auth/server_verify_token")
            .and_then(Value::as_str)
            .and_then(|token| crypto::decrypt_message(token, &server_key.key, "").ok());
        token.map_or_else(
            || ResponseTemplate::new(400).set_body_json(envelope(&Value::Null)),
            |token| {
                gpgauth(200, "false", "stage0")
                    .insert_header(
                        "X-GPGAuth-Verify-Response",
                        String::from_utf8(token).unwrap(),
                    )
                    .set_body_json(envelope(&Value::Null))
            },
        )
    }
}

/// An answer with the `X-GPGAuth-*` headers of a login step, as Passbolt sends them.
fn gpgauth(status: u16, authenticated: &str, progress: &str) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .insert_header("X-GPGAuth-Version", "1.3.0")
        .insert_header("X-GPGAuth-Authenticated", authenticated)
        .insert_header("X-GPGAuth-Progress", progress)
}

fn envelope(body: &Value) -> Value {
    json!({"header": {"status": "success", "message": "The operation was successful."}, "body": body})
}

fn ada() -> Value {
    json!({
        "id": ADA_ID,
        "username": "ada@passbolt.test",
        "gpgkey": {"id": "8b6c3a10-0000-4000-8000-000000008888", "armored_key": ADA_PUBLIC}
    })
}

/// PHP `quotemeta(urlencode($armored))`, as the server sends the challenge.
fn php_quotemeta_urlencode(text: &str) -> String {
    url::form_urlencoded::byte_serialize(text.as_bytes())
        .collect::<String>()
        .chars()
        .flat_map(|character| match character {
            '.' | '\\' | '+' | '*' | '?' | '[' | '^' | ']' | '$' | '(' | ')' => {
                vec!['\\', character]
            }
            character => vec![character],
        })
        .collect()
}

fn fixture(json: &str) -> Value {
    serde_json::from_str(json).unwrap()
}

fn resource_types() -> Value {
    json!([{"id": PASSWORD_AND_DESCRIPTION_ID, "slug": "password-and-description", "name": "Password and description"}])
}

/// A v4 resource whose secret is encrypted for ada.
fn resource(secret: &str) -> Value {
    let ada_key = crypto::parse_public_key(ADA_PUBLIC).unwrap();
    json!({
        "id": RESOURCE_ID,
        "name": "GitHub",
        "username": "ada",
        "resource_type_id": PASSWORD_AND_DESCRIPTION_ID,
        "created": "2025-09-16T10:00:00+00:00",
        "modified": "2025-09-16T10:00:00+00:00",
        "secrets": [{"user_id": ADA_ID, "data": crypto::encrypt_message(secret.as_bytes(), &[&ada_key]).unwrap()}]
    })
}

#[test]
fn login_answers_the_gpgauth_challenge() {
    let passbolt = Passbolt::new();

    let client = passbolt.login();

    assert_eq!(client.user_id(), ADA_ID);
    assert_eq!(passbolt.requests("POST", "/auth/login.json").len(), 2);
}

#[test]
fn a_resource_view_is_decrypted_json() {
    let passbolt = Passbolt::new();
    passbolt.on(
        "GET",
        &format!("/resources/{RESOURCE_ID}.json"),
        &resource(r#"{"password":"s3cr3t","description":"prod"}"#),
    );
    passbolt.on("GET", "/resource-types.json", &resource_types());

    let view: Value = serde_json::from_str(
        &passbolt
            .login()
            .get_resource_view(RESOURCE_ID.into())
            .unwrap(),
    )
    .unwrap();

    assert_eq!(view["name"], "GitHub");
    assert_eq!(view["password"], "s3cr3t");
    assert_eq!(view["description"], "prod");
    assert_eq!(view["resource_type"], "password-and-description");
}

#[test]
fn a_resource_is_created_from_json() {
    let passbolt = Passbolt::new();
    passbolt.on_status("GET", "/metadata/types/settings.json", 404, &Value::Null);
    passbolt.on("GET", "/resource-types.json", &resource_types());
    passbolt.on("POST", "/resources.json", &resource("{}"));

    passbolt
        .login()
        .create_resource(r#"{"name": "GitHub", "username": "ada", "password": "s3cr3t"}"#.into())
        .unwrap();

    let created = &passbolt.requests("POST", "/resources.json")[0];
    assert_eq!(created["name"], "GitHub");
    assert_eq!(created["resource_type_id"], PASSWORD_AND_DESCRIPTION_ID);
    assert_eq!(created["secrets"][0]["user_id"], ADA_ID);
}

#[test]
fn an_invalid_resource_json_is_an_invalid_argument() {
    let passbolt = Passbolt::new();

    let error = passbolt
        .login()
        .create_resource(r#"{"nmae": "typo"}"#.into())
        .err()
        .unwrap();

    assert!(
        matches!(error, PassboltFfiError::InvalidArgument { .. }),
        "{error}"
    );
    assert_eq!(passbolt.requests("POST", "/resources.json").len(), 0);
}

#[test]
fn a_resource_moves_into_a_folder() {
    let passbolt = Passbolt::new();
    let folder_id = "5f6e7d8c-0000-4000-8000-0000000000f1";
    passbolt.on(
        "PUT",
        &format!("/move/resource/{RESOURCE_ID}.json"),
        &Value::Null,
    );

    passbolt
        .login()
        .move_resource(RESOURCE_ID.into(), Some(folder_id.into()))
        .unwrap();

    assert_eq!(
        passbolt.requests("PUT", &format!("/move/resource/{RESOURCE_ID}.json")),
        [json!({"folder_parent_id": folder_id})]
    );
}

#[test]
fn an_api_error_keeps_its_status() {
    let passbolt = Passbolt::new();
    passbolt.on_status(
        "DELETE",
        &format!("/resources/{RESOURCE_ID}.json"),
        404,
        &Value::Null,
    );

    let error = passbolt
        .login()
        .delete_resource(RESOURCE_ID.into())
        .unwrap_err();

    assert!(
        matches!(error, PassboltFfiError::Api { status: 404, .. }),
        "{error}"
    );
}

#[test]
fn the_server_key_is_fetched_with_its_computed_fingerprint() {
    let passbolt = Passbolt::new();
    passbolt.answer_server_verification();

    let server_key = fetch_server_key(passbolt.server.uri(), false).unwrap();

    assert_eq!(server_key.armored_key, SERVER_PUBLIC);
    assert_eq!(
        server_key.fingerprint,
        crypto::public_key_fingerprint(SERVER_PUBLIC).unwrap()
    );
}

#[test]
fn a_pinned_server_key_is_proven_at_login() {
    let passbolt = Passbolt::new();
    passbolt.answer_server_verification();

    let client = passbolt
        .login_with(FfiLoginOptions {
            server_public_key: Some(SERVER_PUBLIC.into()),
            ..FfiLoginOptions::default()
        })
        .unwrap();

    assert_eq!(client.user_id(), ADA_ID);
    assert_eq!(passbolt.requests("POST", "/auth/verify.json").len(), 1);
}

#[test]
fn a_server_without_the_pinned_key_is_refused_before_login() {
    let passbolt = Passbolt::new();
    passbolt.answer_server_verification();

    let Err(error) = passbolt.login_with(FfiLoginOptions {
        server_public_key: Some(BETTY_PUBLIC.into()),
        ..FfiLoginOptions::default()
    }) else {
        panic!("logged in to a server without the pinned key")
    };

    assert!(error.to_string().contains("identity"), "{error}");
    assert_eq!(
        passbolt.requests("POST", "/auth/login.json"),
        Vec::<Value>::new()
    );
}

/// Ada's share of the metadata key: its private key, encrypted for her.
fn ada_share_of_the_metadata_key() -> String {
    let private_key = json!({
        "object_type": "PASSBOLT_METADATA_PRIVATE_KEY",
        "domain": "https://passbolt.test",
        "fingerprint": crypto::public_key_fingerprint(METADATA_PUBLIC).unwrap(),
        "armored_key": METADATA_PRIVATE,
        "passphrase": ""
    });
    let ada_key = crypto::parse_public_key(ADA_PUBLIC).unwrap();
    crypto::encrypt_message(private_key.to_string().as_bytes(), &[&ada_key]).unwrap()
}

#[test]
fn the_active_metadata_key_fingerprint_is_given_to_pin() {
    let passbolt = Passbolt::new();
    passbolt.on(
        "GET",
        "/metadata/keys.json",
        &json!([{
            "id": "4f1d2e3c-0000-4000-8000-0000000000a1",
            "fingerprint": crypto::public_key_fingerprint(METADATA_PUBLIC).unwrap(),
            "armored_key": METADATA_PUBLIC,
            "created": "2025-09-01T10:00:00+00:00",
            "modified": "2025-09-01T10:00:00+00:00",
            "deleted": null,
            "expired": null,
            "metadata_private_keys": [{
                "id": "4f1d2e3c-0000-4000-8000-0000000000b1",
                "metadata_key_id": "4f1d2e3c-0000-4000-8000-0000000000a1",
                "user_id": ADA_ID,
                "data": ada_share_of_the_metadata_key(),
                "created": "2025-09-01T10:00:00+00:00",
                "modified": "2025-09-01T10:00:00+00:00"
            }]
        }]),
    );

    let fingerprint = passbolt.login().metadata_key_fingerprint().unwrap();

    assert_eq!(
        fingerprint,
        Some(crypto::public_key_fingerprint(METADATA_PUBLIC).unwrap())
    );
}

#[test]
fn keeping_the_session_alive_reads_the_user() {
    let passbolt = Passbolt::new();
    let client = passbolt.login();
    let before = passbolt.requests("GET", "/users/me.json").len();

    client.keep_alive().unwrap();

    assert_eq!(passbolt.requests("GET", "/users/me.json").len(), before + 1);
}

#[test]
fn a_missing_resource_view_keeps_the_not_found_status() {
    let passbolt = Passbolt::new();
    passbolt.on_status(
        "GET",
        &format!("/resources/{RESOURCE_ID}.json"),
        404,
        &Value::Null,
    );

    let error = passbolt
        .login()
        .get_resource_view(RESOURCE_ID.into())
        .unwrap_err();

    assert!(
        matches!(
            error,
            PassboltFfiError::Api { status: 404, .. } | PassboltFfiError::NotFound { .. }
        ),
        "{error}"
    );
}

#[test]
fn a_folder_is_created_at_the_root() {
    let passbolt = Passbolt::new();
    passbolt.on("POST", "/folders.json", &fixture(FOLDER));

    let folder = passbolt.login().create_folder("Ops".into(), None).unwrap();

    assert_eq!(folder.id, FOLDER_ID);
    let created = &passbolt.requests("POST", "/folders.json")[0];
    assert_eq!(created["name"], "Ops");
    assert_eq!(created["folder_parent_id"], Value::Null);
}

#[test]
fn a_folder_is_renamed() {
    let passbolt = Passbolt::new();
    let folder_path = format!("/folders/{FOLDER_ID}.json");
    passbolt.on("PUT", &folder_path, &fixture(FOLDER));

    passbolt
        .login()
        .rename_folder(FOLDER_ID.into(), "Infra".into())
        .unwrap();

    assert_eq!(
        passbolt.requests("PUT", &folder_path),
        [json!({"name": "Infra"})]
    );
}

#[test]
fn a_folder_is_deleted_with_its_content() {
    let passbolt = Passbolt::new();
    let folder_path = format!("/folders/{FOLDER_ID}.json");
    passbolt.on("DELETE", &folder_path, &Value::Null);

    passbolt
        .login()
        .delete_folder_with_content(FOLDER_ID.into())
        .unwrap();

    assert_eq!(passbolt.queries("DELETE", &folder_path), ["cascade=1"]);
}

#[test]
fn a_user_is_created_with_the_id_of_their_role() {
    let passbolt = Passbolt::new();
    passbolt.on("GET", "/roles.json", &fixture(ROLES));
    passbolt.on("POST", "/users.json", &fixture(USERS)["betty"]);

    passbolt
        .login()
        .create_user(
            "betty@passbolt.test".into(),
            "Betty".into(),
            "Test".into(),
            "user".into(),
        )
        .unwrap();

    let created = &passbolt.requests("POST", "/users.json")[0];
    assert_eq!(created["username"], "betty@passbolt.test");
    assert_eq!(created["role_id"], "a58de6d3-f52c-5080-b79b-a601a647ac85");
    assert_eq!(
        created["profile"],
        json!({"first_name": "Betty", "last_name": "Test"})
    );
}

#[test]
fn the_delete_blockers_of_a_user_are_listed() {
    let passbolt = Passbolt::new();
    passbolt.on_error(
        "DELETE",
        &format!("/users/{BETTY_ID}/dry-run.json"),
        400,
        &fixture(USER_DELETE_DRY_RUN_ERRORS),
    );

    let blockers = passbolt
        .login()
        .user_delete_blockers(BETTY_ID.into())
        .unwrap();

    assert_eq!(blockers.resources.len(), 2);
    assert_eq!(blockers.groups[0].name, "Ops");
    assert_eq!(
        blockers.groups_to_delete,
        ["9c7d4b20-0000-4000-8000-000000000961"]
    );
}

#[test]
fn a_user_without_blockers_is_deleted_without_transfer() {
    let passbolt = Passbolt::new();
    let user_path = format!("/users/{BETTY_ID}.json");
    passbolt.on(
        "DELETE",
        &format!("/users/{BETTY_ID}/dry-run.json"),
        &Value::Null,
    );
    passbolt.on("DELETE", &user_path, &Value::Null);

    passbolt
        .login()
        .delete_user_with_transfer(BETTY_ID.into(), CAROL_ID.into())
        .unwrap();

    assert_eq!(passbolt.requests("DELETE", &user_path), [Value::Null]);
}

#[test]
fn a_blocked_user_gives_what_they_own_to_their_successor() {
    let passbolt = Passbolt::new();
    let user_path = format!("/users/{BETTY_ID}.json");
    passbolt.on_error(
        "DELETE",
        &format!("/users/{BETTY_ID}/dry-run.json"),
        400,
        &fixture(USER_DELETE_DRY_RUN_ERRORS),
    );
    passbolt.on("DELETE", &user_path, &Value::Null);

    passbolt
        .login()
        .delete_user_with_transfer(BETTY_ID.into(), CAROL_ID.into())
        .unwrap();

    assert_eq!(
        passbolt.requests("DELETE", &user_path),
        [json!({"transfer": {
            "owners": [
                {"id": "3e4f5a60-0000-4000-8000-0000000000a2", "aco_foreign_key": RESOURCE_ID},
                {"id": "3e4f5a60-0000-4000-8000-0000000000b2", "aco_foreign_key": "7a5b2c30-0000-4000-8000-0000000000e2"}
            ],
            "managers": [{"id": "6d8e9f10-0000-4000-8000-0000000000c2", "group_id": GROUP_ID}]
        }})]
    );
}

#[test]
fn a_successor_without_access_is_refused_before_the_deletion() {
    let passbolt = Passbolt::new();
    let user_path = format!("/users/{BETTY_ID}.json");
    passbolt.on_error(
        "DELETE",
        &format!("/users/{BETTY_ID}/dry-run.json"),
        400,
        &fixture(USER_DELETE_DRY_RUN_ERRORS),
    );

    let error = passbolt
        .login()
        .delete_user_with_transfer(BETTY_ID.into(), ADA_ID.into())
        .unwrap_err();

    assert!(
        matches!(error, PassboltFfiError::InvalidArgument { .. }),
        "{error}"
    );
    assert_eq!(passbolt.requests("DELETE", &user_path), Vec::<Value>::new());
}

#[test]
fn a_group_is_created_with_its_managers_and_members() {
    let passbolt = Passbolt::new();
    passbolt.on("POST", "/groups.json", &fixture(GROUP));

    passbolt
        .login()
        .create_group("Ops".into(), vec![BETTY_ID.into()], vec![ADA_ID.into()])
        .unwrap();

    let memberships: Vec<(Value, Value)> = passbolt.requests("POST", "/groups.json")[0]
        ["groups_users"]
        .as_array()
        .unwrap()
        .iter()
        .map(|membership| {
            (
                membership["user_id"].clone(),
                membership["is_admin"].clone(),
            )
        })
        .collect();
    assert_eq!(
        memberships,
        [
            (json!(ADA_ID), json!(true)),
            (json!(BETTY_ID), json!(false))
        ]
    );
}

#[test]
fn a_group_is_renamed() {
    let passbolt = Passbolt::new();
    let group_path = format!("/groups/{GROUP_ID}.json");
    passbolt.on("GET", &group_path, &fixture(GROUP));
    passbolt.on("PUT", &group_path, &fixture(GROUP));

    passbolt
        .login()
        .update_group(
            GROUP_ID.into(),
            Some("Infra".into()),
            vec![],
            vec![],
            vec![],
        )
        .unwrap();

    assert_eq!(
        passbolt.requests("PUT", &group_path),
        [json!({"name": "Infra"})]
    );
}

#[test]
fn the_tags_of_a_resource_are_replaced() {
    let passbolt = Passbolt::new();
    let tags_path = format!("/tags/{RESOURCE_ID}.json");
    passbolt.on("POST", &tags_path, &json!([fixture(TAG)]));

    let tags = passbolt
        .login()
        .set_resource_tags(RESOURCE_ID.into(), vec!["prod".into()])
        .unwrap();

    assert_eq!(tags[0].slug, "prod");
    assert_eq!(
        passbolt.requests("POST", &tags_path),
        [json!({"tags": ["prod"]})]
    );
}

#[test]
fn the_resource_types_are_listed_with_their_schema() {
    let passbolt = Passbolt::new();
    passbolt.on("GET", "/resource-types.json", &fixture(RESOURCE_TYPES));

    let resource_types = passbolt.login().list_resource_types().unwrap();

    assert_eq!(resource_types[0].slug, "password-string");
    let definition: Value =
        serde_json::from_str(resource_types[0].definition.as_deref().unwrap()).unwrap();
    assert_eq!(definition["resource"]["required"], json!(["name"]));
}
