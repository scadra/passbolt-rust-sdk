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

// WASM is single-threaded — futures don't need Send, and wasm_bindgen requires owned params.
#![allow(clippy::future_not_send, clippy::needless_pass_by_value)]

//! Passbolt SDK — WASM binding for browser extensions.
//!
//! Exports `PassboltSession` for authenticated API operations and
//! stateless crypto functions for progressive openpgp.js replacement.

mod http;

use passbolt_sdk::config::SdkConfig;
use passbolt_sdk::error::PassboltError;
use passbolt_sdk::types::{SecretData, TotpData};
use passbolt_sdk::PassboltSdk;
use serde::Serialize;
use wasm_bindgen::prelude::*;

use crate::http::WasmHttpClient;

type Client = PassboltSdk<WasmHttpClient>;

// ── Error conversion ─────────────────────────────────────────────────────────

fn to_js_error(e: PassboltError) -> JsError {
    JsError::new(&e.to_string())
}

/// Plain JS objects, not `Map`s: what JSON gives, so `metadata` and `secret` read as objects.
fn to_js_value<T: serde::Serialize>(val: &T) -> Result<JsValue, JsError> {
    val.serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|error| JsError::new(&error.to_string()))
}

/// The MFA code given at login: verified once, when the server asks.
struct GivenTotpCode(String);

impl passbolt_sdk::MfaProvider for GivenTotpCode {
    fn get_totp_code(&self) -> Result<String, PassboltError> {
        Ok(self.0.clone())
    }
}

/// `options[name]`, if `options` is an object holding it.
fn option(options: &JsValue, name: &str) -> Option<JsValue> {
    if !options.is_object() {
        return None;
    }
    js_sys::Reflect::get(options, &JsValue::from_str(name))
        .ok()
        .filter(|value| !value.is_undefined() && !value.is_null())
}

/// Decrypted secret as exposed to JS.
///
/// `SecretData.raw` is not serialized by the SDK, so the password of a
/// "password-string" resource is folded into `password` here.
#[derive(Serialize)]
struct JsSecretData {
    password: Option<String>,
    description: Option<String>,
    totp: Option<TotpData>,
}

impl From<SecretData> for JsSecretData {
    fn from(secret: SecretData) -> Self {
        Self {
            password: secret.password.or(secret.raw),
            description: secret.description,
            totp: secret.totp,
        }
    }
}

fn build_sdk_config(
    server_url: String,
    private_key_armored: String,
    passphrase: String,
) -> SdkConfig {
    SdkConfig {
        server_url,
        private_key_armored,
        passphrase: secrecy::SecretString::from(passphrase),
        mfa_mode: String::new(),
        mfa_totp_token: String::new(),
        mfa_totp_offset: 0,
        mfa_retrys: 0,
        tls_skip_verify: false,
        tls_client_cert: String::new(),
        tls_client_private_key: String::new(),
        proxy: String::new(),
        server_public_key: String::new(),
        metadata_key_fingerprint: String::new(),
        server_verify_enc_token: String::new(),
        server_verify_token: String::new(),
    }
}

// ── PassboltSession ──────────────────────────────────────────────────────────

/// Authenticated Passbolt session for CRUD operations.
///
/// Usage from JS:
/// ```js
/// const session = await PassboltSession.login(serverUrl, privateKey, passphrase, {
///   csrfTokenProvider: async () => (await browser.cookies.get({ name: "csrfToken", url: serverUrl }))?.value,
///   totpCode: "123456",
/// });
/// const resources = await session.listResources();
/// await session.logout();
/// ```
#[wasm_bindgen]
pub struct PassboltSession {
    client: Client,
}

#[wasm_bindgen]
impl PassboltSession {
    /// Authenticate against a Passbolt server and return a session.
    ///
    /// `options` (optional):
    /// - `csrfTokenProvider`: function returning the `csrfToken` cookie, or a promise of it,
    ///   e.g. with `browser.cookies.get` in an extension. Default: `document.cookie`, readable
    ///   by pages served by Passbolt only.
    /// - `totpCode`: the TOTP code to answer the MFA challenge with.
    #[wasm_bindgen]
    pub async fn login(
        server_url: String,
        private_key_armored: String,
        passphrase: String,
        options: JsValue,
    ) -> Result<Self, JsError> {
        crate::http::set_csrf_token_provider(
            option(&options, "csrfTokenProvider").and_then(|provider| provider.dyn_into().ok()),
        );
        let mfa_provider = option(&options, "totpCode")
            .and_then(|code| code.as_string())
            .map(|code| Box::new(GivenTotpCode(code)) as Box<dyn passbolt_sdk::MfaProvider>);
        let http = WasmHttpClient::new();
        let config = build_sdk_config(server_url, private_key_armored, passphrase);

        let client = Client::login(http, &config, mfa_provider, 1)
            .await
            .map_err(to_js_error)?;

        Ok(Self { client })
    }

    /// Terminate the server-side session.
    #[wasm_bindgen]
    pub async fn logout(&self) {
        self.client.logout().await;
    }

    /// Check if the session is still valid.
    #[wasm_bindgen(js_name = "checkAuth")]
    pub async fn check_auth(&self) -> Result<bool, JsError> {
        self.client.check_auth_status().await.map_err(to_js_error)
    }

    // ── Resources ────────────────────────────────────────────────────────

    /// List all resources (with secrets and permissions).
    #[wasm_bindgen(js_name = "listResources")]
    pub async fn list_resources(&self, search: Option<String>) -> Result<JsValue, JsError> {
        let query = passbolt_sdk::ResourceQuery {
            search,
            ..Default::default()
        };
        let resources = self
            .client
            .get_resources(query)
            .await
            .map_err(to_js_error)?;
        to_js_value(&resources)
    }

    /// Get a single resource by ID.
    #[wasm_bindgen(js_name = "getResource")]
    pub async fn get_resource(&self, id: String) -> Result<JsValue, JsError> {
        let resource = self.client.get_resource(&id).await.map_err(to_js_error)?;
        to_js_value(&resource)
    }

    /// Decrypt a resource's secret. Returns the plaintext secret data as JSON.
    #[wasm_bindgen(js_name = "decryptResourceSecret")]
    pub async fn decrypt_resource_secret(&self, resource_js: JsValue) -> Result<JsValue, JsError> {
        let resource: passbolt_sdk::types::Resource =
            serde_wasm_bindgen::from_value(resource_js)
                .map_err(|error| JsError::new(&format!("Invalid resource: {error}")))?;
        let secret = self
            .client
            .decrypt_resource_secret(&resource)
            .await
            .map_err(to_js_error)?;
        to_js_value(&JsSecretData::from(secret))
    }

    /// A resource with its v5 metadata and its secret decrypted, for every resource type:
    /// `name`, `username`, `uris`, `description`, `password`, `metadata`, `secret`…
    #[wasm_bindgen(js_name = "getResourceView")]
    pub async fn get_resource_view(&self, id: String) -> Result<JsValue, JsError> {
        let view = passbolt_sdk::resource::get::get_resource_view(&self.client, &id)
            .await
            .map_err(|error| JsError::new(&error.to_string()))?;
        to_js_value(&view)
    }

    /// Resources with their v5 metadata decrypted, searched by their decrypted name; their
    /// secrets too with `withSecrets`. A resource that cannot be decrypted has an `error`.
    #[wasm_bindgen(js_name = "listResourceViews")]
    pub async fn list_resource_views(
        &self,
        search: Option<String>,
        with_secrets: bool,
    ) -> Result<JsValue, JsError> {
        let query = passbolt_sdk::ResourceQuery {
            search,
            ..Default::default()
        };
        let views = passbolt_sdk::resource::list::list_resources(
            &self.client,
            query,
            &[],
            with_secrets.then_some(1),
        )
        .await
        .map_err(to_js_error)?;
        to_js_value(&views)
    }

    /// Create a resource of any type from `{name, resource_type?, username?, uris?, password?,
    /// totp?, note?, pin_code?, custom_fields?, metadata_fields?, secret_fields?, …}`.
    /// The type follows the fields and the server's default version when not given.
    #[wasm_bindgen(js_name = "createResource")]
    pub async fn create_resource(&self, new_resource: JsValue) -> Result<JsValue, JsError> {
        let new_resource: passbolt_sdk::resource::create::NewResource =
            serde_wasm_bindgen::from_value(new_resource)
                .map_err(|error| JsError::new(&format!("Invalid resource: {error}")))?;
        let resource = passbolt_sdk::resource::create::create_resource(&self.client, &new_resource)
            .await
            .map_err(to_js_error)?;
        to_js_value(&resource)
    }

    /// Update a resource from the fields to change: `{name?, password?, totp?, remove_totp?,
    /// expired?, …}`; `expired: null` clears the expiry.
    #[wasm_bindgen(js_name = "updateResource")]
    pub async fn update_resource(&self, id: String, changes: JsValue) -> Result<JsValue, JsError> {
        let changes: passbolt_sdk::resource::update::ResourceChanges =
            serde_wasm_bindgen::from_value(changes)
                .map_err(|error| JsError::new(&format!("Invalid changes: {error}")))?;
        let resource = passbolt_sdk::resource::update::update_resource(&self.client, &id, &changes)
            .await
            .map_err(to_js_error)?;
        to_js_value(&resource)
    }

    /// Share a resource with users and groups (`permissionType` 1, 7 or 15), or revoke with -1.
    #[wasm_bindgen(js_name = "shareResource")]
    pub async fn share_resource(
        &self,
        id: String,
        user_ids: Vec<String>,
        group_ids: Vec<String>,
        permission_type: i32,
    ) -> Result<(), JsError> {
        passbolt_sdk::resource::share::share_resource(
            &self.client,
            &id,
            &user_ids,
            &group_ids,
            permission_type,
        )
        .await
        .map_err(to_js_error)
    }

    /// Share a folder, and with `withContent` the sub-folders and resources the user owns.
    #[wasm_bindgen(js_name = "shareFolder")]
    pub async fn share_folder(
        &self,
        id: String,
        user_ids: Vec<String>,
        group_ids: Vec<String>,
        permission_type: i32,
        with_content: bool,
    ) -> Result<(), JsError> {
        passbolt_sdk::folder::share::share_folder(
            &self.client,
            &id,
            &user_ids,
            &group_ids,
            permission_type,
            with_content,
        )
        .await
        .map_err(to_js_error)
    }

    /// Move a resource into a folder, or to the root without one.
    #[wasm_bindgen(js_name = "moveResource")]
    pub async fn move_resource(
        &self,
        id: String,
        folder_id: Option<String>,
    ) -> Result<(), JsError> {
        self.client
            .move_resource(&id, folder_id.as_deref())
            .await
            .map_err(to_js_error)
    }

    /// Move a folder into another one, or to the root without one.
    #[wasm_bindgen(js_name = "moveFolder")]
    pub async fn move_folder(&self, id: String, folder_id: Option<String>) -> Result<(), JsError> {
        self.client
            .move_folder(&id, folder_id.as_deref())
            .await
            .map_err(to_js_error)
    }

    /// Delete a resource.
    #[wasm_bindgen(js_name = "deleteResource")]
    pub async fn delete_resource(&self, id: String) -> Result<(), JsError> {
        self.client.delete_resource(&id).await.map_err(to_js_error)
    }

    // ── Folders ──────────────────────────────────────────────────────────

    /// List all folders.
    #[wasm_bindgen(js_name = "listFolders")]
    pub async fn list_folders(&self) -> Result<JsValue, JsError> {
        let folders = self
            .client
            .get_folders(passbolt_sdk::FolderQuery::default())
            .await
            .map_err(to_js_error)?;
        to_js_value(&folders)
    }

    /// Get a single folder by ID.
    #[wasm_bindgen(js_name = "getFolder")]
    pub async fn get_folder(&self, id: String) -> Result<JsValue, JsError> {
        let folder = self.client.get_folder(&id).await.map_err(to_js_error)?;
        to_js_value(&folder)
    }

    // ── Users ────────────────────────────────────────────────────────────

    /// List all users.
    #[wasm_bindgen(js_name = "listUsers")]
    pub async fn list_users(&self) -> Result<JsValue, JsError> {
        let users = self
            .client
            .get_users(passbolt_sdk::UserQuery::default())
            .await
            .map_err(to_js_error)?;
        to_js_value(&users)
    }

    /// Get the currently logged-in user.
    #[wasm_bindgen(js_name = "getMe")]
    pub async fn get_me(&self) -> Result<JsValue, JsError> {
        let me = self.client.get_me().await.map_err(to_js_error)?;
        to_js_value(&me)
    }

    // ── Groups ───────────────────────────────────────────────────────────

    /// List all groups.
    #[wasm_bindgen(js_name = "listGroups")]
    pub async fn list_groups(&self) -> Result<JsValue, JsError> {
        let groups = self
            .client
            .get_groups(passbolt_sdk::GroupQuery::default())
            .await
            .map_err(to_js_error)?;
        to_js_value(&groups)
    }

    // ── Tags ─────────────────────────────────────────────────────────────

    /// List all tags.
    #[wasm_bindgen(js_name = "getTags")]
    pub async fn get_tags(&self) -> Result<JsValue, JsError> {
        let tags = self.client.get_tags().await.map_err(to_js_error)?;
        to_js_value(&tags)
    }

    // ── Comments ─────────────────────────────────────────────────────────

    /// Get comments for a resource.
    #[wasm_bindgen(js_name = "getComments")]
    pub async fn get_comments(&self, resource_id: String) -> Result<JsValue, JsError> {
        let comments = self
            .client
            .get_comments(&resource_id)
            .await
            .map_err(to_js_error)?;
        to_js_value(&comments)
    }

    /// Create a comment on a resource.
    #[wasm_bindgen(js_name = "createComment")]
    pub async fn create_comment(
        &self,
        resource_id: String,
        content: String,
        parent_id: Option<String>,
    ) -> Result<JsValue, JsError> {
        let comment = self
            .client
            .create_comment(&resource_id, &content, parent_id.as_deref())
            .await
            .map_err(to_js_error)?;
        to_js_value(&comment)
    }

    // ── Sharing ──────────────────────────────────────────────────────────

    /// Search for users and groups (AROs) for sharing.
    #[wasm_bindgen(js_name = "searchAros")]
    pub async fn search_aros(&self, search: String) -> Result<JsValue, JsError> {
        let aros = self
            .client
            .search_aros(&search)
            .await
            .map_err(to_js_error)?;
        to_js_value(&aros)
    }

    // ── HIBP ─────────────────────────────────────────────────────────────

    /// Check if a password has been exposed in data breaches.
    /// Returns the number of times found (0 = not breached).
    #[wasm_bindgen(js_name = "checkPasswordPwned")]
    pub async fn check_password_pwned(&self, password: String) -> Result<u64, JsError> {
        self.client
            .check_password_pwned(&password)
            .await
            .map_err(to_js_error)
    }
}

// ── Stateless crypto functions ───────────────────────────────────────────────

/// Decrypt a PGP-armored message with a private key.
/// For progressive openpgp.js replacement.
#[wasm_bindgen(js_name = "decryptMessage")]
pub fn decrypt_message(
    armored_message: &str,
    private_key_armored: &str,
    passphrase: &str,
) -> Result<Vec<u8>, JsError> {
    let key = passbolt_sdk::crypto::parse_private_key(private_key_armored)
        .map_err(|error| JsError::new(&error.to_string()))?;
    passbolt_sdk::crypto::decrypt_message(armored_message, &key.key, passphrase)
        .map_err(|error| JsError::new(&error.to_string()))
}

/// Encrypt a plaintext message for one or more PGP public keys.
/// Returns the PGP-armored ciphertext.
#[wasm_bindgen(js_name = "encryptMessage")]
pub fn encrypt_message(
    plaintext: &[u8],
    public_keys_armored: Vec<String>,
) -> Result<String, JsError> {
    let parsed: Result<Vec<_>, _> = public_keys_armored
        .iter()
        .map(|armored_key| passbolt_sdk::crypto::parse_public_key(armored_key))
        .collect();
    let keys = parsed.map_err(|error| JsError::new(&error.to_string()))?;
    let key_refs: Vec<_> = keys.iter().collect();
    passbolt_sdk::crypto::encrypt_message(plaintext, &key_refs)
        .map_err(|error| JsError::new(&error.to_string()))
}

/// Parse a PGP private key and return its fingerprint (hex uppercase).
#[wasm_bindgen(js_name = "getKeyFingerprint")]
pub fn get_key_fingerprint(private_key_armored: &str) -> Result<String, JsError> {
    let key = passbolt_sdk::crypto::parse_private_key(private_key_armored)
        .map_err(|error| JsError::new(&error.to_string()))?;
    Ok(key.fingerprint.clone())
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use secrecy::ExposeSecret;
    use serde_json::json;

    use super::*;

    const SERVER_PRIVATE: &str =
        include_str!("../../passbolt-sdk/tests/fixtures/keys/server_private.asc");
    const SERVER_PUBLIC: &str =
        include_str!("../../passbolt-sdk/tests/fixtures/keys/server_public.asc");

    fn secret(password: Option<&str>, raw: Option<&str>) -> SecretData {
        SecretData {
            password: password.map(String::from),
            raw: raw.map(String::from),
            ..SecretData::default()
        }
    }

    #[rstest]
    #[case::password_string(None, Some("raw password"), Some("raw password"))]
    #[case::json_secret(Some("json password"), None, Some("json password"))]
    #[case::password_wins_over_raw(Some("json password"), Some("raw"), Some("json password"))]
    #[case::empty(None, None, None)]
    fn test_js_secret_data_password_falls_back_to_raw(
        #[case] password: Option<&str>,
        #[case] raw: Option<&str>,
        #[case] expected: Option<&str>,
    ) {
        let js_secret = JsSecretData::from(secret(password, raw));

        assert_eq!(js_secret.password.as_deref(), expected);
    }

    #[test]
    fn test_js_secret_data_serializes_password_of_password_string_resource() {
        let js_secret = JsSecretData::from(secret(None, Some("raw password")));

        let serialized = serde_json::to_value(&js_secret).unwrap();

        assert_eq!(
            serialized,
            json!({ "password": "raw password", "description": null, "totp": null })
        );
    }

    #[test]
    fn test_js_secret_data_keeps_description_and_totp() {
        let secret_data: SecretData = serde_json::from_value(json!({
            "password": "pw",
            "description": "note",
            "totp": { "secret_key": "JBSWY3DPEHPK3PXP", "algorithm": "SHA1", "digits": 6, "period": 30, "issuer": null }
        }))
        .unwrap();

        let serialized = serde_json::to_value(JsSecretData::from(secret_data)).unwrap();

        assert_eq!(serialized["description"], "note");
        assert_eq!(serialized["totp"]["secret_key"], "JBSWY3DPEHPK3PXP");
        assert_eq!(serialized["totp"]["digits"], 6);
    }

    #[test]
    fn test_build_sdk_config_copies_credentials_without_mfa_or_tls_bypass() {
        let config = build_sdk_config(
            "https://passbolt.test".into(),
            "armored key".into(),
            "secret passphrase".into(),
        );

        assert_eq!(config.server_url, "https://passbolt.test");
        assert_eq!(config.private_key_armored, "armored key");
        assert_eq!(config.passphrase.expose_secret(), "secret passphrase");
        assert_eq!(config.mfa_mode, "");
        assert!(!config.tls_skip_verify);
        assert_eq!(config.proxy, "");
    }

    #[test]
    fn test_encrypt_then_decrypt_message_round_trips() {
        let armored = encrypt_message(b"top secret", vec![SERVER_PUBLIC.into()]).unwrap();

        let plaintext = decrypt_message(&armored, SERVER_PRIVATE, "").unwrap();

        assert_eq!(plaintext, b"top secret");
    }

    #[test]
    fn test_get_key_fingerprint_is_uppercase_hex() {
        let fingerprint = get_key_fingerprint(SERVER_PRIVATE).unwrap();

        assert_eq!(fingerprint.len(), 40);
        assert!(fingerprint
            .chars()
            .all(|character| matches!(character, '0'..='9' | 'A'..='F')));
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;

    const SERVER_PRIVATE: &str =
        include_str!("../../passbolt-sdk/tests/fixtures/keys/server_private.asc");
    const BETTY_PUBLIC: &str =
        include_str!("../../passbolt-sdk/tests/fixtures/keys/betty_public.asc");

    const ADA_PRIVATE: &str =
        include_str!("../../passbolt-sdk/tests/fixtures/keys/ada_private.asc");
    const ADA_PUBLIC: &str = include_str!("../../passbolt-sdk/tests/fixtures/keys/ada_public.asc");
    const ADA_ID: &str = "8b6c3a10-0000-4000-8000-00000000a0da";

    /// A `fetch` answering the `GPGAuth` login with `challenge`, and `/users/me.json`.
    fn passbolt_fetch(challenge: &str) -> JsValue {
        let factory = js_sys::Function::new_with_args(
            "challenge, userId, armoredKey, fingerprint",
            r#"
            const json = (body, headers = {}) =>
                new Response(JSON.stringify({ header: { status: "success" }, body }), { headers });
            return async (request) => {
                const body = request.method === "POST" ? await request.text() : "";
                if (request.url.endsWith("/auth/login.json")) {
                    return body.includes("user_token_result")
                        ? json({ user: { id: userId } }, { "X-GPGAuth-Authenticated": "true" })
                        : json(null, { "X-GPGAuth-User-Auth-Token": encodeURIComponent(challenge) });
                }
                if (request.url.includes("/users/me.json")) {
                    return json({
                        id: userId,
                        username: "ada@passbolt.test",
                        gpgkey: { armored_key: armoredKey, fingerprint },
                    });
                }
                return new Response("{}", { status: 404 });
            };
            "#,
        );
        let arguments = js_sys::Array::of4(
            &challenge.into(),
            &ADA_ID.into(),
            &ADA_PUBLIC.into(),
            &get_key_fingerprint(ADA_PRIVATE).unwrap().into(),
        );
        factory.apply(&JsValue::NULL, &arguments).unwrap()
    }

    #[wasm_bindgen_test]
    async fn test_login_answers_gpgauth_with_the_provided_csrf_token() {
        let token = format!("gpgauthv1.3.0|36|{}|gpgauthv1.3.0", uuid::Uuid::new_v4());
        let challenge = encrypt_message(token.as_bytes(), vec![ADA_PUBLIC.into()]).unwrap();
        let global = js_sys::global();
        let real_fetch = js_sys::Reflect::get(&global, &"fetch".into()).unwrap();
        js_sys::Reflect::set(&global, &"fetch".into(), &passbolt_fetch(&challenge)).unwrap();
        let options = js_sys::Object::new();
        let provider = js_sys::Function::new_no_args("return 'csrf-from-provider';");
        js_sys::Reflect::set(&options, &"csrfTokenProvider".into(), &provider).unwrap();

        let session = PassboltSession::login(
            "http://127.0.0.1:1".into(),
            ADA_PRIVATE.into(),
            "ada-passphrase".into(),
            options.into(),
        )
        .await;

        js_sys::Reflect::set(&global, &"fetch".into(), &real_fetch).unwrap();
        crate::http::set_csrf_token_provider(None);
        if let Err(error) = session {
            let error = JsValue::from(error);
            panic!("{:?}", js_sys::Reflect::get(&error, &"message".into()));
        }
    }

    #[wasm_bindgen_test]
    fn test_maps_reach_js_as_plain_objects() {
        let value = to_js_value(&serde_json::json!({"metadata": {"name": "GitHub"}})).unwrap();

        let metadata = js_sys::Reflect::get(&value, &"metadata".into()).unwrap();
        let name = js_sys::Reflect::get(&metadata, &"name".into()).unwrap();
        assert_eq!(name.as_string().as_deref(), Some("GitHub"));
    }

    #[wasm_bindgen_test]
    fn test_login_options_are_read_from_an_object() {
        let options = js_sys::Object::new();
        js_sys::Reflect::set(&options, &"totpCode".into(), &"123456".into()).unwrap();
        js_sys::Reflect::set(&options, &"absent".into(), &JsValue::NULL).unwrap();

        assert_eq!(
            option(&options, "totpCode")
                .and_then(|code| code.as_string())
                .as_deref(),
            Some("123456")
        );
        assert!(option(&options, "absent").is_none());
        assert!(option(&JsValue::UNDEFINED, "totpCode").is_none());
    }

    #[wasm_bindgen_test]
    fn test_the_given_totp_code_answers_the_mfa_challenge() {
        use passbolt_sdk::MfaProvider;

        assert_eq!(
            GivenTotpCode("123456".into()).get_totp_code().unwrap(),
            "123456"
        );
    }

    #[wasm_bindgen_test]
    fn test_decrypt_message_with_wrong_key_is_error() {
        let armored = encrypt_message(b"for betty", vec![BETTY_PUBLIC.into()]).unwrap();

        let result = decrypt_message(&armored, SERVER_PRIVATE, "");

        assert!(result.is_err());
    }

    #[wasm_bindgen_test]
    fn test_js_secret_data_exposes_raw_password_to_js() {
        let secret = SecretData {
            raw: Some("raw password".into()),
            ..SecretData::default()
        };

        let value = to_js_value(&JsSecretData::from(secret)).unwrap();

        let password = js_sys::Reflect::get(&value, &"password".into()).unwrap();
        assert_eq!(password.as_string().as_deref(), Some("raw password"));
    }
}
