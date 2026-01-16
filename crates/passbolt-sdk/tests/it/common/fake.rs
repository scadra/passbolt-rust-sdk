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

//! In-memory Passbolt API behind the SDK's `HttpClient` trait.
//!
//! Login, MFA and envelopes follow `passbolt_api` (`AuthLoginController`,
//! `GpgAuthenticator`, `MfaRequiredCheckMiddleware`); other endpoints answer
//! canned bodies registered by the test.

#![allow(clippy::unused_async_trait_impl)] // synchronous fake behind an async trait

use std::sync::{Arc, Mutex};

use passbolt_sdk::{HttpClient, HttpResponse, TransportError};
use serde_json::{json, Value};

use super::keys::{TestKey, ADA, SERVER};
use super::{data, ADA_ID, BASE_URL, BETTY_ID, CAROL_ID, CSRF_TOKEN, ERIN_ID};

/// Paths reachable while MFA is pending (`MfaRequiredCheckMiddleware::isRouteWhiteListed`).
const MFA_WHITELIST: [&str; 3] = ["/auth/login", "/auth/logout", "/mfa/verify"];

#[derive(Debug, Clone)]
pub struct RecordedRequest {
    pub method: &'static str,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Value>,
}

impl RecordedRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub const fn json_body(&self) -> &Value {
        self.body.as_ref().unwrap()
    }

    /// Decoded values of the query parameter `name`, in order.
    pub fn query_values(&self, name: &str) -> Vec<String> {
        url::form_urlencoded::parse(self.query.as_bytes())
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
            .collect()
    }

    pub fn query_value(&self, name: &str) -> Option<String> {
        self.query_values(name).into_iter().next()
    }
}

struct Route {
    method: &'static str,
    path: String,
    status: u16,
    message: String,
    body: Value,
}

/// `GET path` answered page by page, with `header.pagination`.
struct PagedList {
    path: String,
    count: usize,
    limit: usize,
    pages: Vec<Value>,
    failing_pages: Vec<(usize, u16)>,
}

/// `(method, path, answers)`: answers (status, body) given once each, in order.
type QueuedAnswers = (
    &'static str,
    String,
    std::collections::VecDeque<(u16, Value)>,
);

#[derive(Default)]
#[allow(clippy::struct_excessive_bools)] // independent switches of the fake server
struct State {
    routes: Vec<Route>,
    /// Answers (status, body) given once each, in order, before the route of the same request.
    queued_answers: Vec<QueuedAnswers>,
    paged_lists: Vec<PagedList>,
    requests: Vec<RecordedRequest>,
    login_token: Option<String>,
    challenge: Option<String>,
    mfa_code: Option<String>,
    mfa_verified: bool,
    mfa_verification_ignored: bool,
    no_csrf_cookie: bool,
    csrf_cookie_sent: bool,
    rotated_csrf_token: Option<String>,
    /// Last `csrfToken` cookie set, as a cookie jar keeps it.
    csrf_cookie: Option<String>,
    no_auth_token_header: bool,
    login_verification_error: Option<(u16, String)>,
    /// The private key the server decrypts verify tokens with; `None` is the real one.
    impostor_key: Option<&'static TestKey>,
    /// `/metadata/types/settings.json`; `None` without the Metadata plugin.
    metadata_types_settings: Option<Value>,
}

/// Clones share their state: keep one to inspect what the SDK sent.
#[derive(Clone)]
pub struct FakePassbolt {
    state: Arc<Mutex<State>>,
}

impl FakePassbolt {
    /// Server where ada can log in.
    pub fn new() -> Self {
        let fake = Self {
            state: Arc::default(),
        };
        fake.on("GET", "/users/me.json", data::user("ada"));
        fake.on("GET", "/auth/verify.json", data::auth_verify(&SERVER));
        fake.on("GET", "/resource-types.json", data::resource_types());
        fake.on("POST", "/auth/logout.json", Value::Null);
        fake
    }

    /// Users (with their public key), resource types and roles.
    pub fn with_directory(&self) {
        let names = ["ada", "betty", "carol", "erin"];
        for (id, name) in [ADA_ID, BETTY_ID, CAROL_ID, ERIN_ID].into_iter().zip(names) {
            self.on("GET", &format!("/users/{id}.json"), data::user(name));
        }
        self.on("GET", "/users.json", data::users(&names));
        self.on("GET", "/resource-types.json", data::resource_types());
        self.on("GET", "/roles.json", data::roles());
    }

    /// A server serving the real server public key while holding `key`.
    pub fn impersonated_with(&self, key: &'static TestKey) {
        self.state.lock().unwrap().impostor_key = Some(key);
    }

    /// The Metadata plugin with `types` and `keys` settings.
    pub fn with_metadata_settings(&self, types: Value, keys: Value) {
        self.on("GET", "/metadata/types/settings.json", types.clone());
        self.on("GET", "/metadata/keys/settings.json", keys);
        self.state.lock().unwrap().metadata_types_settings = Some(types);
    }

    /// Answer `method path` with `body` in a success envelope. Query strings are
    /// ignored; the last registration wins.
    pub fn on(&self, method: &'static str, path: &str, body: Value) {
        self.route(method, path, 200, "", body);
    }

    pub fn on_error(&self, method: &'static str, path: &str, status: u16) {
        self.on_error_saying(method, path, status, "");
    }

    /// Error envelope whose `header.message` is `message`.
    pub fn on_error_saying(&self, method: &'static str, path: &str, status: u16, message: &str) {
        self.route(method, path, status, message, Value::Null);
    }

    /// Answer `method path` with an error envelope carrying `body`, as validation errors do.
    pub fn on_error_with_body(
        &self,
        method: &'static str,
        path: &str,
        status: u16,
        message: &str,
        body: Value,
    ) {
        self.route(method, path, status, message, body);
    }

    fn route(&self, method: &'static str, path: &str, status: u16, message: &str, body: Value) {
        let mut state = self.state.lock().unwrap();
        state
            .routes
            .retain(|route| !(route.method == method && route.path == path));
        state.routes.push(Route {
            method,
            path: path.to_string(),
            status,
            message: message.to_string(),
            body,
        });
    }

    /// Answer the next requests to `method path` with `answers` (status, body), one each, then
    /// with its route.
    pub fn on_in_turn(&self, method: &'static str, path: &str, answers: Vec<(u16, Value)>) {
        self.state
            .lock()
            .unwrap()
            .queued_answers
            .push((method, path.to_string(), answers.into()));
    }

    /// Answer `GET path?page=N` with `pages[N - 1]` (an empty list past the end) and
    /// `header.pagination` announcing `count` items, `limit` per page.
    pub fn on_pages(&self, path: &str, count: usize, limit: usize, pages: Vec<Value>) {
        let mut state = self.state.lock().unwrap();
        state
            .paged_lists
            .retain(|paged_list| paged_list.path != path);
        state.paged_lists.push(PagedList {
            path: path.to_string(),
            count,
            limit,
            pages,
            failing_pages: Vec::new(),
        });
    }

    /// Answer `page` of the list registered with `on_pages` with an error `status`.
    pub fn fail_page(&self, path: &str, page: usize, status: u16) {
        self.state
            .lock()
            .unwrap()
            .paged_lists
            .iter_mut()
            .find(|paged_list| paged_list.path == path)
            .unwrap_or_else(|| panic!("no pages registered for {path}"))
            .failing_pages
            .push((page, status));
    }

    /// Stage 1 of the login without the `X-GPGAuth-User-Auth-Token` header.
    pub fn without_auth_token_header(&self) {
        self.state.lock().unwrap().no_auth_token_header = true;
    }

    /// Answer stage 2 of the login (the decrypted token) with `status` and `message`.
    pub fn fail_login_verification(&self, status: u16, message: &str) {
        self.state.lock().unwrap().login_verification_error = Some((status, message.to_string()));
    }

    /// TOTP required after login, as `MfaRequiredCheckMiddleware` enforces it.
    /// The `passbolt_mfa` cookie expires: the next request is challenged again.
    pub fn expire_mfa(&self) {
        self.state.lock().unwrap().mfa_verified = false;
    }

    /// Accept TOTP codes but keep challenging, as a misbehaving server would.
    pub fn ignore_mfa_verification(&self) {
        self.state.lock().unwrap().mfa_verification_ignored = true;
    }

    pub fn require_mfa(&self, code: &str) {
        self.state.lock().unwrap().mfa_code = Some(code.to_string());
    }

    /// Send `plaintext` as the `GPGAuth` challenge instead of a valid token.
    pub fn send_challenge(&self, plaintext: &str) {
        self.state.lock().unwrap().challenge = Some(plaintext.to_string());
    }

    /// Set a new `csrfToken` cookie with the next GET, as the server may do mid-session.
    pub fn rotate_csrf_token(&self, token: &str) {
        self.state.lock().unwrap().rotated_csrf_token = Some(token.to_string());
    }

    pub fn without_csrf_cookie(&self) {
        self.state.lock().unwrap().no_csrf_cookie = true;
    }

    pub fn requests_to(&self, method: &str, path: &str) -> Vec<RecordedRequest> {
        let state = self.state.lock().unwrap();
        state
            .requests
            .iter()
            .filter(|request| request.method == method && request.path == path)
            .cloned()
            .collect()
    }

    /// Number of requests received so far, whatever their route.
    pub fn request_count(&self) -> usize {
        self.state.lock().unwrap().requests.len()
    }

    /// What the fake now answers to `method path`, as it stored it.
    pub fn stored(&self, method: &str, path: &str) -> Value {
        self.route_body(method, path).unwrap_or(Value::Null)
    }

    /// Body of the single `method path` request.
    pub fn body_of(&self, method: &str, path: &str) -> Value {
        let requests = self.requests_to(method, path);
        assert_eq!(requests.len(), 1, "{method} {path} calls");
        requests[0].json_body().clone()
    }

    fn handle(
        &self,
        method: &'static str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> HttpResponse {
        let path_and_query = url.strip_prefix(BASE_URL).unwrap_or(url);
        let (path, query) = path_and_query
            .split_once('?')
            .unwrap_or((path_and_query, ""));
        let body: Option<Value> = body
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| serde_json::from_slice(bytes).unwrap());
        self.state.lock().unwrap().requests.push(RecordedRequest {
            method,
            path: path.to_string(),
            query: query.to_string(),
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
                .collect(),
            body: body.clone(),
        });

        let body = body.unwrap_or(Value::Null);
        match (method, path) {
            ("POST", "/auth/login.json") => self.gpgauth_login(&body),
            ("POST", "/auth/verify.json") => self.verify_server(&body),
            ("POST", "/mfa/verify/totp.json") => self.verify_totp(&body),
            ("POST", "/resources.json") => self
                .refuse_resource(&body, path, true)
                .unwrap_or_else(|| self.canned_response(method, path)),
            ("POST", _) if path.starts_with("/share/simulate/resource/") => {
                self.simulate_share(path, &body)
            }
            ("PUT", _) if path.starts_with("/share/resource/") => self
                .refuse_share(path)
                .unwrap_or_else(|| self.canned_response(method, path)),
            // Unless the test set a route, an error for instance.
            ("POST", SESSION_KEYS_PATH) if self.route_body(method, path).is_none() => {
                self.create_session_keys_bundle(&body)
            }
            ("PUT" | "DELETE", _)
                if path.starts_with(SESSION_KEYS_PREFIX)
                    && self.route_body(method, path).is_none() =>
            {
                self.write_session_keys_bundle(method, path, &body)
            }
            ("PUT", _) if path.starts_with("/resources/") => {
                self.refuse_resource(&body, path, false).unwrap_or_else(|| {
                    self.store_metadata(path, &body);
                    self.canned_response(method, path)
                })
            }
            _ if self.mfa_pending()
                && !MFA_WHITELIST.iter().any(|prefix| path.starts_with(prefix)) =>
            {
                // The 302 to /mfa/verify/error.json, as seen after reqwest follows it.
                json_response(
                    403,
                    "MFA authentication is required.",
                    "/mfa/verify/error.json",
                    &data::mfa_error(),
                )
            }
            _ => {
                let mut response = self
                    .paged_response(method, path, query)
                    .unwrap_or_else(|| self.canned_response(method, path));
                if method == "GET" {
                    self.set_csrf_cookie(&mut response);
                }
                response
            }
        }
    }

    /// Like `CsrfProtectionMiddleware`: the cookie comes with the first GET, not with login.
    fn set_csrf_cookie(&self, response: &mut HttpResponse) {
        let mut state = self.state.lock().unwrap();
        if let Some(token) = state.rotated_csrf_token.take() {
            response
                .headers
                .push(("set-cookie-name".into(), format!("csrfToken={token}")));
            state.csrf_cookie = Some(token);
        } else if !state.no_csrf_cookie && !state.csrf_cookie_sent {
            state.csrf_cookie_sent = true;
            // What NativeHttpClient exposes for the `csrfToken` cookie.
            response
                .headers
                .push(("set-cookie-name".into(), format!("csrfToken={CSRF_TOKEN}")));
            state.csrf_cookie = Some(CSRF_TOKEN.to_string());
        }
    }

    /// The 400 of `MetadataResourceDto`, `MetadataSettingsAwareTrait` and `ResourcesTable` v5 rules.
    fn refuse_resource(&self, body: &Value, url: &str, creating: bool) -> Option<HttpResponse> {
        let refuse = |message: &str, errors: Value| Some(json_response(400, message, url, &errors));
        let present = |field: &str| !body[field].is_null();
        let v5_fields = ["metadata", "metadata_key_id", "metadata_key_type"];
        let settings = self.state.lock().unwrap().metadata_types_settings.clone();

        if !v5_fields.into_iter().any(present) {
            let refused = creating
                && settings
                    .is_some_and(|settings| settings["allow_creation_of_v4_resources"] == false);
            return refused.then(|| {
                json_response(
                    400,
                    "Resource creation with cleartext metadata not allowed.",
                    url,
                    &Value::Null,
                )
            });
        }
        let Some(settings) = settings else {
            return refuse("V5 metadata format is not enabled.", Value::Null);
        };
        if !v5_fields.into_iter().all(present) {
            return refuse("Few fields are missing for the V5.", Value::Null);
        }
        if ["name", "username", "uri", "description"]
            .into_iter()
            .any(present)
        {
            return refuse("V4 related fields are not supported for V5.", Value::Null);
        }
        if settings["allow_creation_of_v5_resources"] != true {
            return refuse(
                "Resource creation/modification with encrypted metadata not allowed.",
                Value::Null,
            );
        }
        let slug = data::resource_types()
            .as_array()
            .unwrap()
            .iter()
            .find(|resource_type| resource_type["id"] == body["resource_type_id"])
            .map(|resource_type| resource_type["slug"].as_str().unwrap().to_string());
        let errors = if !slug.as_deref().is_some_and(|slug| slug.starts_with("v5-")) {
            json!({"resource_type_id": {"inList": "The resource type should be one of the following: v5 types."}})
        } else if creating && slug.as_deref() == Some("v5-password-string") {
            json!({"resource_type_id": {"isNotV5PasswordStringType": "It is not allowed to create v5-password-string resource types."}})
        } else if !["user_key", "shared_key"]
            .contains(&body["metadata_key_type"].as_str().unwrap_or_default())
        {
            json!({"metadata_key_type": {"inList": "The metadata key type should be one of the following: user_key, shared_key."}})
        } else {
            return None;
        };
        refuse("Could not validate resource data.", errors)
    }

    /// `ShareController::dryRun`: the users who gain or lose access, group members included.
    fn simulate_share(&self, path: &str, body: &Value) -> HttpResponse {
        if let Some(refused) = self.refuse_share(path) {
            return refused;
        }
        let resource_id = path
            .trim_start_matches("/share/simulate/resource/")
            .trim_end_matches(".json");
        let mut permissions = self.permissions_of(resource_id);
        let before = users_with_access(&permissions);
        for change in body["permissions"].as_array().into_iter().flatten() {
            let existing = permissions.iter().position(|permission| {
                change["id"].is_string() && permission["id"] == change["id"]
            });
            match (existing, change["delete"] == true) {
                (Some(index), true) => {
                    permissions.remove(index);
                }
                (Some(index), false) => permissions[index]["type"] = change["type"].clone(),
                (None, _) => permissions.push(change.clone()),
            }
        }
        let after = users_with_access(&permissions);
        let as_users = |user_ids: Vec<&String>| {
            user_ids
                .into_iter()
                .map(|user_id| json!({"User": {"id": user_id}}))
                .collect::<Vec<_>>()
        };
        json_response(
            200,
            "The operation was successful.",
            path,
            &json!({"changes": {
                "added": as_users(after.difference(&before).collect()),
                "removed": as_users(before.difference(&after).collect()),
            }}),
        )
    }

    /// `ShareController`: a resource with personal metadata cannot be shared.
    fn refuse_share(&self, path: &str) -> Option<HttpResponse> {
        let resource_id = path
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .trim_end_matches(".json");
        let resource = self.route_body("GET", &format!("/resources/{resource_id}.json"))?;
        (resource["metadata"].is_string() && resource["metadata_key_type"] == "user_key").then(
            || {
                json_response(
                    400,
                    "Resource metadata key type is invalid.",
                    path,
                    &Value::Null,
                )
            },
        )
    }

    /// `MetadataSessionKeyCreateController`: the bundle joins the user's list.
    fn create_session_keys_bundle(&self, body: &Value) -> HttpResponse {
        let mut bundles = self.session_keys_bundles();
        let bundle = json!({
            "id": format!("4a5b6c7d-0000-4000-8000-{:012}", bundles.len() + 1000),
            "user_id": ADA_ID,
            "data": body["data"],
            "created": next_modified(&bundles),
            "modified": next_modified(&bundles),
        });
        bundles.push(bundle.clone());
        self.on("GET", SESSION_KEYS_PATH, Value::Array(bundles));
        json_response(200, "", SESSION_KEYS_PATH, &bundle)
    }

    /// `MetadataSessionKeyUpdateService` (409 unless `modified` is the stored one) and
    /// `MetadataSessionKeyDeleteService`.
    fn write_session_keys_bundle(&self, method: &str, path: &str, body: &Value) -> HttpResponse {
        let id = path
            .trim_start_matches(SESSION_KEYS_PREFIX)
            .trim_end_matches(".json");
        let mut bundles = self.session_keys_bundles();
        let Some(index) = bundles.iter().position(|bundle| bundle["id"] == id) else {
            return json_response(404, "The session key does not exist.", path, &Value::Null);
        };
        if method == "DELETE" {
            bundles.remove(index);
            self.on("GET", SESSION_KEYS_PATH, Value::Array(bundles));
            return json_response(200, "", path, &Value::Null);
        }
        if bundles[index]["modified"] != body["modified"] {
            return json_response(
                409,
                "The metadata session key data has changed.",
                path,
                &Value::Null,
            );
        }
        let modified = next_modified(&bundles);
        bundles[index]["data"] = body["data"].clone();
        bundles[index]["modified"] = modified.into();
        let bundle = bundles[index].clone();
        self.on("GET", SESSION_KEYS_PATH, Value::Array(bundles));
        json_response(200, "", path, &bundle)
    }

    fn session_keys_bundles(&self) -> Vec<Value> {
        self.route_body("GET", SESSION_KEYS_PATH)
            .and_then(|bundles| bundles.as_array().cloned())
            .unwrap_or_default()
    }

    /// Later GETs of the resource return the v5 metadata it was updated with.
    fn store_metadata(&self, path: &str, body: &Value) {
        let Some(mut resource) = self.route_body("GET", path) else {
            return;
        };
        for field in ["metadata", "metadata_key_id", "metadata_key_type"] {
            if !body[field].is_null() {
                resource[field] = body[field].clone();
            }
        }
        self.on("GET", path, resource);
    }

    fn permissions_of(&self, resource_id: &str) -> Vec<Value> {
        self.route_body("GET", &format!("/permissions/resource/{resource_id}.json"))
            .and_then(|permissions| permissions.as_array().cloned())
            .unwrap_or_default()
    }

    fn route_body(&self, method: &str, path: &str) -> Option<Value> {
        let state = self.state.lock().unwrap();
        state
            .routes
            .iter()
            .find(|route| route.method == method && route.path == path)
            .map(|route| route.body.clone())
    }

    fn mfa_pending(&self) -> bool {
        let state = self.state.lock().unwrap();
        state.mfa_code.is_some() && !state.mfa_verified
    }

    fn canned_response(&self, method: &str, path: &str) -> HttpResponse {
        let mut state = self.state.lock().unwrap();
        let queued_answer = state
            .queued_answers
            .iter_mut()
            .find(|(queued_method, queued_path, _)| *queued_method == method && queued_path == path)
            .and_then(|(_, _, answers)| answers.pop_front());
        if let Some((status, body)) = queued_answer {
            return json_response(status, "", path, &body);
        }
        state
            .routes
            .iter()
            .find(|route| route.method == method && route.path == path)
            .map_or_else(
                || {
                    json_response(
                        404,
                        &format!("fake: no route for {method} {path}"),
                        path,
                        &Value::Null,
                    )
                },
                |route| json_response(route.status, &route.message, path, &route.body),
            )
    }

    fn paged_response(&self, method: &str, path: &str, query: &str) -> Option<HttpResponse> {
        if method != "GET" {
            return None;
        }
        let page: usize = url::form_urlencoded::parse(query.as_bytes())
            .find(|(key, _)| key == "page")
            .map_or(1, |(_, value)| value.parse().unwrap());
        let (count, limit, failing_status, items) = {
            let state = self.state.lock().unwrap();
            let paged_list = state
                .paged_lists
                .iter()
                .find(|paged_list| paged_list.path == path)?;
            let failing_status = paged_list
                .failing_pages
                .iter()
                .find(|(failing_page, _)| *failing_page == page)
                .map(|(_, status)| *status);
            let items = paged_list.pages.get(page - 1).cloned();
            let answer = (paged_list.count, paged_list.limit, failing_status, items);
            drop(state);
            answer
        };
        if let Some(status) = failing_status {
            return Some(json_response(
                status,
                "fake: page refused",
                path,
                &Value::Null,
            ));
        }
        let mut response = json_response(200, "", path, &items.unwrap_or_else(|| json!([])));
        let mut envelope: Value = serde_json::from_slice(&response.body).unwrap();
        envelope["header"]["pagination"] = json!({ "count": count, "page": page, "limit": limit });
        response.body = serde_json::to_vec(&envelope).unwrap();
        Some(response)
    }

    /// `GpgAuthenticator::_stage0`: decrypt the token, return it if it is a `GPGAuth` nonce.
    fn verify_server(&self, body: &Value) -> HttpResponse {
        const URL: &str = "/auth/verify.json";
        if body.pointer("/gpg_auth/keyid").and_then(Value::as_str)
            != Some(ADA.fingerprint().as_str())
        {
            return json_response(
                400,
                "There is no user associated with this key.",
                URL,
                &Value::Null,
            );
        }
        let server_key = self.state.lock().unwrap().impostor_key.unwrap_or(&SERVER);
        let nonce = body
            .pointer("/gpg_auth/server_verify_token")
            .and_then(Value::as_str)
            .and_then(|token| server_key.try_decrypt(token));
        let Some(nonce) = nonce else {
            return json_response(400, "Decryption failed.", URL, &Value::Null);
        };
        let mut response = json_response(400, "The authentication failed.", URL, &Value::Null);
        let parts: Vec<&str> = nonce.split('|').collect();
        if let [version, "36", id, version_again] = parts.as_slice() {
            if version == version_again
                && *version == "gpgauthv1.3.0"
                && uuid::Uuid::try_parse(id).is_ok()
            {
                response
                    .headers
                    .push(("X-GPGAuth-Verify-Response".into(), nonce));
            }
        }
        response
    }

    fn gpgauth_login(&self, body: &Value) -> HttpResponse {
        const URL: &str = "/auth/login.json";
        if body.pointer("/gpg_auth/keyid").and_then(Value::as_str)
            != Some(ADA.fingerprint().as_str())
        {
            return json_response(
                400,
                "There is no user associated with this key.",
                URL,
                &Value::Null,
            );
        }
        let Some(user_token_result) = body
            .pointer("/gpg_auth/user_token_result")
            .and_then(Value::as_str)
        else {
            let token = format!("gpgauthv1.3.0|36|{}|gpgauthv1.3.0", uuid::Uuid::new_v4());
            let (challenge, send_token_header) = {
                let mut state = self.state.lock().unwrap();
                let challenge = ADA.encrypt(state.challenge.as_deref().unwrap_or(&token));
                state.login_token = Some(token);
                (challenge, !state.no_auth_token_header)
            };
            // Stage 1 is a partial success: error envelope with status 200.
            let mut response = envelope(
                200,
                "error",
                "Please decrypt this token.",
                URL,
                &Value::Null,
            );
            response
                .headers
                .push(("X-GPGAuth-Progress".into(), "stage1".into()));
            if send_token_header {
                response.headers.push((
                    "X-GPGAuth-User-Auth-Token".into(),
                    php_quotemeta_urlencode(&challenge),
                ));
            }
            return response;
        };

        let (expected_token, verification_error) = {
            let state = self.state.lock().unwrap();
            (
                state.login_token.clone(),
                state.login_verification_error.clone(),
            )
        };
        if expected_token.as_deref() != Some(user_token_result) {
            return json_response(400, "The authentication failed.", URL, &Value::Null);
        }
        if let Some((status, message)) = verification_error {
            return json_response(status, &message, URL, &Value::Null);
        }
        let mut response = json_response(
            200,
            "You are successfully logged in.",
            URL,
            &data::user("ada"),
        );
        response
            .headers
            .push(("X-GPGAuth-Authenticated".into(), "true".into()));
        response
    }

    fn verify_totp(&self, body: &Value) -> HttpResponse {
        const URL: &str = "/mfa/verify/totp.json";
        {
            let mut state = self.state.lock().unwrap();
            if body["totp"].as_str() != state.mfa_code.as_deref() {
                return json_response(400, "The OTP is not valid.", URL, &Value::Null);
            }
            state.mfa_verified = !state.mfa_verification_ignored;
        }
        let mut response = json_response(
            200,
            "The multi-factor authentication was a success.",
            URL,
            &Value::Null,
        );
        response
            .headers
            .push(("set-cookie-name".into(), "passbolt_mfa=verified".into()));
        response
    }
}

/// PHP `quotemeta(urlencode($s))`, as `GpgAuthenticator` sends the challenge.
const SESSION_KEYS_PATH: &str = "/metadata/session-keys.json";
const SESSION_KEYS_PREFIX: &str = "/metadata/session-keys/";

/// A `modified` later than every bundle's.
fn next_modified(bundles: &[Value]) -> String {
    let latest = bundles
        .iter()
        .filter_map(|bundle| bundle["modified"].as_str())
        .filter_map(|modified| chrono::DateTime::parse_from_rfc3339(modified).ok())
        .max()
        .map_or_else(chrono::Utc::now, |latest| latest.to_utc());
    (latest + chrono::Duration::seconds(1)).to_rfc3339()
}

fn php_quotemeta_urlencode(input: &str) -> String {
    url::form_urlencoded::byte_serialize(input.as_bytes())
        .collect::<String>()
        .replace('.', "\\.")
        .replace('+', "\\+")
}

fn json_response(code: u16, message: &str, url: &str, body: &Value) -> HttpResponse {
    let status = if code >= 400 { "error" } else { "success" };
    envelope(code, status, message, url, body)
}

/// Passbolt JSON envelope.
fn envelope(code: u16, status: &str, message: &str, url: &str, body: &Value) -> HttpResponse {
    let envelope = json!({
        "header": { "id": uuid::Uuid::new_v4().to_string(), "status": status, "servertime": 1_757_000_000,
                    "action": uuid::Uuid::new_v4().to_string(), "message": message, "url": url, "code": code },
        "body": body
    });
    HttpResponse {
        status: code,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: serde_json::to_vec(&envelope).unwrap(),
    }
}

impl HttpClient for FakePassbolt {
    fn cookie(&self, _url: &str, name: &str) -> Option<String> {
        let state = self.state.lock().unwrap();
        state.csrf_cookie.clone().filter(|_| name == "csrfToken")
    }

    async fn get(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<HttpResponse, TransportError> {
        Ok(self.handle("GET", url, headers, None))
    }

    async fn post(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse, TransportError> {
        Ok(self.handle("POST", url, headers, Some(body)))
    }

    async fn put(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse, TransportError> {
        Ok(self.handle("PUT", url, headers, Some(body)))
    }

    async fn delete(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<HttpResponse, TransportError> {
        Ok(self.handle("DELETE", url, headers, None))
    }

    async fn delete_with_body(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse, TransportError> {
        Ok(self.handle("DELETE", url, headers, Some(body)))
    }
}

/// Users given access by `permissions`: the users, and the members of the groups.
fn users_with_access(permissions: &[Value]) -> std::collections::BTreeSet<String> {
    let group = data::group();
    permissions
        .iter()
        .flat_map(|permission| {
            let aro_id = permission["aro_foreign_key"].as_str().unwrap_or_default();
            if permission["aro"] == "Group" && group["id"] == aro_id {
                group["groups_users"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|membership| membership["user_id"].as_str().unwrap().to_string())
                    .collect()
            } else {
                vec![aro_id.to_string()]
            }
        })
        .collect()
}
