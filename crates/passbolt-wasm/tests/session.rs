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

//! `PassboltSession` against a `fetch` answering the `GPGAuth` login as Passbolt does.
//! Run in Node: `cargo test -p passbolt-wasm --target wasm32-unknown-unknown`.

#![cfg(target_arch = "wasm32")]
// WASM is single-threaded: futures don't need Send.
#![allow(clippy::future_not_send)]

use passbolt_wasm::{encrypt_message, get_key_fingerprint, PassboltSession};
use serde_json::{json, Value};
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::wasm_bindgen_test;

const ADA_PRIVATE: &str = include_str!("../../passbolt-sdk/tests/fixtures/keys/ada_private.asc");
const ADA_PUBLIC: &str = include_str!("../../passbolt-sdk/tests/fixtures/keys/ada_public.asc");
const ADA_PASSPHRASE: &str = "ada-passphrase";
const ADA_ID: &str = "8b6c3a10-0000-4000-8000-00000000a0da";
const SERVER_URL: &str = "http://127.0.0.1:1";
const FOLDER_ID: &str = "5f6e7d8c-0000-4000-8000-0000000000f1";
const RESOURCE_ID: &str = "7a5b2c30-0000-4000-8000-0000000000e1";
const OTHER_RESOURCE_ID: &str = "7a5b2c30-0000-4000-8000-0000000000e2";
const BETTY_ID: &str = "8b6c3a10-0000-4000-8000-000000000be7";
const CAROL_ID: &str = "8b6c3a10-0000-4000-8000-0000000ca201";
const GROUP_ID: &str = "9c7d4b20-0000-4000-8000-000000000960";

const FOLDER: &str = include_str!("../../passbolt-sdk/tests/fixtures/data/folder.json");
const FAVORITE: &str = include_str!("../../passbolt-sdk/tests/fixtures/data/favorite.json");
const GROUP: &str = include_str!("../../passbolt-sdk/tests/fixtures/data/group.json");
const ROLES: &str = include_str!("../../passbolt-sdk/tests/fixtures/data/roles.json");
const USERS: &str = include_str!("../../passbolt-sdk/tests/fixtures/data/users.json");
const USER_DELETE_DRY_RUN_ERRORS: &str =
    include_str!("../../passbolt-sdk/tests/fixtures/data/user_delete_dry_run_errors.json");

/// The routes `fetch` answers after the login, and the requests it receives.
struct Passbolt {
    routes: js_sys::Array,
    fetch: JsValue,
}

impl Passbolt {
    /// Installs a `fetch` answering the `GPGAuth` login of ada and `/users/me.json`.
    fn new() -> Self {
        let token = format!("gpgauthv1.3.0|36|{}|gpgauthv1.3.0", uuid::Uuid::new_v4());
        let challenge = encrypt_message(token.as_bytes(), vec![ADA_PUBLIC.into()]).unwrap();
        let factory = js_sys::Function::new_with_args(
            "challenge, userId, armoredKey, fingerprint, routes",
            r#"
            const answer = (status, body, headers = {}) =>
                new Response(
                    JSON.stringify({
                        header: { status: status < 400 ? "success" : "error", message: "" },
                        body,
                    }),
                    { status, headers: { "X-GPGAuth-Version": "1.3.0", ...headers } },
                );
            const step = (authenticated, progress, headers) => ({
                "X-GPGAuth-Authenticated": authenticated,
                "X-GPGAuth-Progress": progress,
                ...headers,
            });
            const requests = [];
            const fetch = async (request) => {
                const text = request.method === "GET" ? "" : await request.text();
                const url = new URL(request.url);
                if (url.pathname === "/auth/login.json") {
                    return text.includes("user_token_result")
                        ? answer(200, { user: { id: userId } }, step("true", "complete", { "X-GPGAuth-Refer": "/" }))
                        : answer(200, null, step("false", "stage1", {
                              "X-GPGAuth-User-Auth-Token": encodeURIComponent(challenge),
                          }));
                }
                if (url.pathname === "/users/me.json") {
                    return answer(200, {
                        id: userId,
                        username: "ada@passbolt.test",
                        gpgkey: { armored_key: armoredKey, fingerprint },
                    });
                }
                let body = null;
                try { body = JSON.parse(text); } catch {}
                requests.push({ method: request.method, path: url.pathname, query: decodeURIComponent(url.search.slice(1)), body });
                const route = routes.find(
                    (route) => route.method === request.method && route.path === url.pathname,
                );
                return route ? answer(route.status, route.body) : answer(404, null);
            };
            fetch.requests = requests;
            return fetch;
            "#,
        );
        let routes = js_sys::Array::new();
        let arguments: js_sys::Array = [
            JsValue::from_str(&challenge),
            JsValue::from_str(ADA_ID),
            JsValue::from_str(ADA_PUBLIC),
            JsValue::from_str(&get_key_fingerprint(ADA_PRIVATE).unwrap()),
            routes.clone().into(),
        ]
        .into_iter()
        .collect();
        let fetch = factory.apply(&JsValue::NULL, &arguments).unwrap();
        js_sys::Reflect::set(&js_sys::global(), &"fetch".into(), &fetch).unwrap();
        Self { routes, fetch }
    }

    fn on(&self, http_method: &str, url_path: &str, body: &Value) {
        self.on_status(http_method, url_path, 200, body);
    }

    /// From 400, an error answer as the server sends it: an `error` header, the failure in `body`.
    fn on_status(&self, http_method: &str, url_path: &str, status: u16, body: &Value) {
        let route =
            json!({"method": http_method, "path": url_path, "status": status, "body": body});
        self.routes.push(&from_json(&route));
    }

    async fn login(&self) -> PassboltSession {
        let options = js_sys::Object::new();
        let csrf_token_provider = js_sys::Function::new_no_args("return 'csrf-token';");
        js_sys::Reflect::set(&options, &"csrfTokenProvider".into(), &csrf_token_provider).unwrap();
        let session = PassboltSession::login(
            SERVER_URL.into(),
            ADA_PRIVATE.into(),
            ADA_PASSPHRASE.into(),
            options.into(),
        )
        .await;
        ok(session)
    }

    fn received(&self, http_method: &str, url_path: &str) -> Vec<Value> {
        let requests = js_sys::Reflect::get(&self.fetch, &"requests".into()).unwrap();
        let Value::Array(requests) = to_json(&requests) else {
            panic!("the requests are not an array")
        };
        requests
            .into_iter()
            .filter(|request| request["method"] == http_method && request["path"] == url_path)
            .collect()
    }

    fn requests(&self, http_method: &str, url_path: &str) -> Vec<Value> {
        self.received(http_method, url_path)
            .into_iter()
            .map(|request| request["body"].clone())
            .collect()
    }

    fn queries(&self, http_method: &str, url_path: &str) -> Vec<Value> {
        self.received(http_method, url_path)
            .into_iter()
            .map(|request| request["query"].clone())
            .collect()
    }
}

/// The value, or a panic with the message of the JS error.
fn ok<T>(result: Result<T, JsError>) -> T {
    result.unwrap_or_else(|error| panic!("{}", message(error)))
}

fn message(error: JsError) -> String {
    let error = JsValue::from(error);
    js_sys::Reflect::get(&error, &"message".into())
        .unwrap()
        .as_string()
        .unwrap_or_default()
}

fn to_json(value: &JsValue) -> Value {
    let text = js_sys::JSON::stringify(value).unwrap();
    serde_json::from_str(&String::from(text)).unwrap()
}

fn from_json(value: &Value) -> JsValue {
    js_sys::JSON::parse(&value.to_string()).unwrap()
}

fn fixture(json: &str) -> Value {
    serde_json::from_str(json).unwrap()
}

#[wasm_bindgen_test]
async fn a_folder_is_created_at_the_root() {
    let passbolt = Passbolt::new();
    passbolt.on("POST", "/folders.json", &fixture(FOLDER));

    let folder = ok(passbolt
        .login()
        .await
        .create_folder("Ops".into(), None)
        .await);

    assert_eq!(to_json(&folder)["id"], FOLDER_ID);
    let created = &passbolt.requests("POST", "/folders.json")[0];
    assert_eq!(created["name"], "Ops");
    assert_eq!(created["folder_parent_id"], Value::Null);
}

#[wasm_bindgen_test]
async fn a_folder_is_renamed() {
    let passbolt = Passbolt::new();
    let folder_path = format!("/folders/{FOLDER_ID}.json");
    passbolt.on("PUT", &folder_path, &fixture(FOLDER));

    ok(passbolt
        .login()
        .await
        .rename_folder(FOLDER_ID.into(), "Infra".into())
        .await);

    assert_eq!(
        passbolt.requests("PUT", &folder_path),
        [json!({"name": "Infra"})]
    );
}

#[wasm_bindgen_test]
async fn a_folder_is_deleted_with_its_content() {
    let passbolt = Passbolt::new();
    let folder_path = format!("/folders/{FOLDER_ID}.json");
    passbolt.on("DELETE", &folder_path, &Value::Null);

    ok(passbolt
        .login()
        .await
        .delete_folder_with_content(FOLDER_ID.into())
        .await);

    assert_eq!(passbolt.queries("DELETE", &folder_path), ["cascade=1"]);
}

#[wasm_bindgen_test]
async fn the_folder_tree_nests_a_folder_in_its_parent() {
    let passbolt = Passbolt::new();
    let mut child = fixture(FOLDER);
    child["id"] = json!("5f6e7d8c-0000-4000-8000-0000000000f2");
    child["name"] = json!("Databases");
    child["folder_parent_id"] = json!(FOLDER_ID);
    passbolt.on("GET", "/folders.json", &json!([fixture(FOLDER), child]));

    let tree = ok(passbolt.login().await.get_folder_tree().await);

    let tree = to_json(&tree);
    assert_eq!(tree.as_array().map(Vec::len), Some(1));
    assert_eq!(tree[0]["folder"]["name"], "Ops");
    assert_eq!(tree[0]["children"][0]["folder"]["name"], "Databases");
}

#[wasm_bindgen_test]
async fn the_session_gives_the_user_and_the_server() {
    let passbolt = Passbolt::new();

    let session = passbolt.login().await;

    assert_eq!(session.user_id(), ADA_ID);
    assert_eq!(session.base_url(), SERVER_URL);
}

#[wasm_bindgen_test]
async fn the_favorite_resources_are_listed() {
    let passbolt = Passbolt::new();
    passbolt.on("GET", "/resources.json", &json!([]));

    ok(passbolt
        .login()
        .await
        .list_resources(None, Some(true), None)
        .await);

    let query = passbolt.queries("GET", "/resources.json")[0].to_string();
    assert!(query.contains("filter[is-favorite]=1"), "{query}");
    assert!(!query.contains("is-owned-by-me"), "{query}");
}

#[wasm_bindgen_test]
async fn a_resource_is_added_to_the_favorites() {
    let passbolt = Passbolt::new();
    passbolt.on(
        "POST",
        &format!("/favorites/resource/{RESOURCE_ID}.json"),
        &fixture(FAVORITE),
    );

    let favorite = ok(passbolt
        .login()
        .await
        .add_favorite(RESOURCE_ID.into())
        .await);

    assert_eq!(to_json(&favorite)["foreign_key"], RESOURCE_ID);
}

#[wasm_bindgen_test]
async fn resources_are_deleted_one_by_one() {
    let passbolt = Passbolt::new();
    for id in [RESOURCE_ID, OTHER_RESOURCE_ID] {
        passbolt.on("DELETE", &format!("/resources/{id}.json"), &Value::Null);
    }

    ok(passbolt
        .login()
        .await
        .delete_resources(vec![RESOURCE_ID.into(), OTHER_RESOURCE_ID.into()])
        .await);

    for id in [RESOURCE_ID, OTHER_RESOURCE_ID] {
        let deleted = passbolt.received("DELETE", &format!("/resources/{id}.json"));
        assert_eq!(deleted.len(), 1, "{id}");
    }
}

#[wasm_bindgen_test]
async fn a_user_is_created_with_the_id_of_their_role() {
    let passbolt = Passbolt::new();
    passbolt.on("GET", "/roles.json", &fixture(ROLES));
    passbolt.on("POST", "/users.json", &fixture(USERS)["betty"]);

    ok(passbolt
        .login()
        .await
        .create_user(
            "betty@passbolt.test".into(),
            "Betty".into(),
            "Test".into(),
            "user".into(),
        )
        .await);

    let created = &passbolt.requests("POST", "/users.json")[0];
    assert_eq!(created["username"], "betty@passbolt.test");
    assert_eq!(created["role_id"], "a58de6d3-f52c-5080-b79b-a601a647ac85");
    assert_eq!(
        created["profile"],
        json!({"first_name": "Betty", "last_name": "Test"})
    );
}

#[wasm_bindgen_test]
async fn a_group_is_created_with_its_managers_and_members() {
    let passbolt = Passbolt::new();
    passbolt.on("POST", "/groups.json", &fixture(GROUP));

    ok(passbolt
        .login()
        .await
        .create_group("Ops".into(), vec![BETTY_ID.into()], vec![ADA_ID.into()])
        .await);

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

#[wasm_bindgen_test]
async fn a_group_is_renamed() {
    let passbolt = Passbolt::new();
    let group_path = format!("/groups/{GROUP_ID}.json");
    passbolt.on("GET", &group_path, &fixture(GROUP));
    passbolt.on("PUT", &group_path, &fixture(GROUP));

    ok(passbolt
        .login()
        .await
        .update_group(
            GROUP_ID.into(),
            Some("Infra".into()),
            vec![],
            vec![],
            vec![],
        )
        .await);

    assert_eq!(
        passbolt.requests("PUT", &group_path),
        [json!({"name": "Infra"})]
    );
}

#[wasm_bindgen_test]
async fn the_delete_blockers_of_a_user_are_listed() {
    let passbolt = Passbolt::new();
    passbolt.on_status(
        "DELETE",
        &format!("/users/{BETTY_ID}/dry-run.json"),
        400,
        &fixture(USER_DELETE_DRY_RUN_ERRORS),
    );

    let blockers = ok(passbolt
        .login()
        .await
        .user_delete_blockers(BETTY_ID.into())
        .await);

    let blockers = to_json(&blockers);
    assert_eq!(blockers["resources"].as_array().map(Vec::len), Some(2));
    assert_eq!(blockers["groups"][0]["name"], "Ops");
    assert_eq!(
        blockers["groups_to_delete"],
        json!(["9c7d4b20-0000-4000-8000-000000000961"])
    );
}

#[wasm_bindgen_test]
async fn a_user_without_blockers_is_deleted_without_transfer() {
    let passbolt = Passbolt::new();
    let user_path = format!("/users/{BETTY_ID}.json");
    passbolt.on(
        "DELETE",
        &format!("/users/{BETTY_ID}/dry-run.json"),
        &Value::Null,
    );
    passbolt.on("DELETE", &user_path, &Value::Null);

    ok(passbolt
        .login()
        .await
        .delete_user_with_transfer(BETTY_ID.into(), CAROL_ID.into())
        .await);

    assert_eq!(passbolt.requests("DELETE", &user_path), [Value::Null]);
}

#[wasm_bindgen_test]
async fn a_blocked_user_gives_what_they_own_to_their_successor() {
    let passbolt = Passbolt::new();
    let user_path = format!("/users/{BETTY_ID}.json");
    passbolt.on_status(
        "DELETE",
        &format!("/users/{BETTY_ID}/dry-run.json"),
        400,
        &fixture(USER_DELETE_DRY_RUN_ERRORS),
    );
    passbolt.on("DELETE", &user_path, &Value::Null);

    ok(passbolt
        .login()
        .await
        .delete_user_with_transfer(BETTY_ID.into(), CAROL_ID.into())
        .await);

    assert_eq!(
        passbolt.requests("DELETE", &user_path),
        [json!({"transfer": {
            "owners": [
                {"id": "3e4f5a60-0000-4000-8000-0000000000a2", "aco_foreign_key": RESOURCE_ID},
                {"id": "3e4f5a60-0000-4000-8000-0000000000b2", "aco_foreign_key": OTHER_RESOURCE_ID}
            ],
            "managers": [{"id": "6d8e9f10-0000-4000-8000-0000000000c2", "group_id": GROUP_ID}]
        }})]
    );
}

#[wasm_bindgen_test]
async fn a_successor_without_access_is_refused_before_the_deletion() {
    let passbolt = Passbolt::new();
    let user_path = format!("/users/{BETTY_ID}.json");
    passbolt.on_status(
        "DELETE",
        &format!("/users/{BETTY_ID}/dry-run.json"),
        400,
        &fixture(USER_DELETE_DRY_RUN_ERRORS),
    );

    let deletion = passbolt
        .login()
        .await
        .delete_user_with_transfer(BETTY_ID.into(), ADA_ID.into())
        .await;

    assert!(deletion.is_err());
    assert_eq!(passbolt.requests("DELETE", &user_path), Vec::<Value>::new());
}
