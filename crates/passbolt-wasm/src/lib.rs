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

#[wasm_bindgen(typescript_custom_section)]
const TYPESCRIPT_TYPES: &str = include_str!("types.d.ts");

#[wasm_bindgen]
extern "C" {
    /// The `LoginOptions` of `types.d.ts`; optional, so its own type rather than a `JsValue`.
    #[wasm_bindgen(typescript_type = "LoginOptions")]
    pub type LoginOptions;
}

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

/// The pins are the armored server key and the metadata key fingerprint; empty for none.
fn build_sdk_config(
    server_url: String,
    private_key_armored: String,
    passphrase: String,
    server_public_key: String,
    metadata_key_fingerprint: String,
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
        server_public_key,
        metadata_key_fingerprint,
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
    ///   by pages served by Passbolt only, or in Node the cookie the server set.
    /// - `totpCode`: the TOTP code to answer the MFA challenge with.
    /// - `serverPublicKey`: the armored server key pinned with `fetchServerKey`; each login
    ///   then checks the server holds its private key.
    /// - `metadataKeyFingerprint`: the shared metadata key pinned with
    ///   `metadataKeyFingerprint()`; shared metadata is then only encrypted for that key.
    #[wasm_bindgen]
    pub async fn login(
        server_url: String,
        private_key_armored: String,
        passphrase: String,
        options: Option<LoginOptions>,
    ) -> Result<Self, JsError> {
        let options = options.map_or(JsValue::UNDEFINED, JsValue::from);
        crate::http::set_csrf_token_provider(
            option(&options, "csrfTokenProvider").and_then(|provider| provider.dyn_into().ok()),
        );
        let mfa_provider = option(&options, "totpCode")
            .and_then(|code| code.as_string())
            .map(|code| Box::new(GivenTotpCode(code)) as Box<dyn passbolt_sdk::MfaProvider>);
        let http = WasmHttpClient::new();
        let pin = |name: &str| {
            option(&options, name)
                .and_then(|value| value.as_string())
                .unwrap_or_default()
        };
        let config = build_sdk_config(
            server_url,
            private_key_armored,
            passphrase,
            pin("serverPublicKey"),
            pin("metadataKeyFingerprint"),
        );

        let client = Client::login(http, &config, mfa_provider, 1)
            .await
            .map_err(to_js_error)?;

        Ok(Self { client })
    }

    /// The server public key to pin, `{ fingerprint, armoredKey }`, the fingerprint computed
    /// from the key: show it to the user, then pass `armoredKey` as `serverPublicKey`.
    #[wasm_bindgen(js_name = "fetchServerKey", unchecked_return_type = "ServerKey")]
    pub async fn fetch_server_key(server_url: String) -> Result<JsValue, JsError> {
        let http = WasmHttpClient::new();
        let (fingerprint, armored_key) =
            passbolt_sdk::auth::fetch_server_key(&http, server_url.trim_end_matches('/'))
                .await
                .map_err(to_js_error)?;
        to_js_value(&serde_json::json!({ "fingerprint": fingerprint, "armoredKey": armored_key }))
    }

    /// The fingerprint of the active shared metadata key, to pin as `metadataKeyFingerprint`;
    /// `undefined` without one.
    #[wasm_bindgen(js_name = "metadataKeyFingerprint")]
    pub async fn metadata_key_fingerprint(&self) -> Result<Option<String>, JsError> {
        let metadata_keys = self.client.metadata_keys().await.map_err(to_js_error)?;
        Ok(metadata_keys.active_fingerprint())
    }

    /// The ID of the logged-in user.
    #[wasm_bindgen(getter, js_name = "userId")]
    pub fn user_id(&self) -> String {
        self.client.user_id.clone()
    }

    /// The server URL.
    #[wasm_bindgen(getter, js_name = "baseUrl")]
    pub fn base_url(&self) -> String {
        self.client.base_url.clone()
    }

    /// Terminate the server-side session.
    #[wasm_bindgen]
    pub async fn logout(&self) {
        self.client.logout().await;
    }

    /// Keep the session alive, as the browser extension does every few minutes.
    #[wasm_bindgen(js_name = "keepAlive")]
    pub async fn keep_alive(&self) -> Result<(), JsError> {
        self.client.keep_alive().await.map_err(to_js_error)
    }

    /// Check if the session is still valid.
    #[wasm_bindgen(js_name = "checkAuth")]
    pub async fn check_auth(&self) -> Result<bool, JsError> {
        self.client.check_auth_status().await.map_err(to_js_error)
    }

    // ── Resources ────────────────────────────────────────────────────────

    /// List all resources (with secrets and permissions), or those whose name holds `search`,
    /// among the favorites with `favoritesOnly`, among those the user owns with `ownedByMe`.
    #[wasm_bindgen(js_name = "listResources")]
    pub async fn list_resources(
        &self,
        search: Option<String>,
        favorites_only: Option<bool>,
        owned_by_me: Option<bool>,
    ) -> Result<JsValue, JsError> {
        let query = passbolt_sdk::ResourceQuery {
            search,
            favorites_only: favorites_only.unwrap_or_default(),
            owned_by_me: owned_by_me.unwrap_or_default(),
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

    /// Get the resources of these IDs.
    #[wasm_bindgen(js_name = "getResourcesByIds")]
    pub async fn get_resources_by_ids(&self, ids: Vec<String>) -> Result<JsValue, JsError> {
        let resources = self
            .client
            .get_resources_by_ids(&ids)
            .await
            .map_err(to_js_error)?;
        to_js_value(&resources)
    }

    /// Get permissions for a resource.
    #[wasm_bindgen(js_name = "getResourcePermissions")]
    pub async fn get_resource_permissions(&self, id: String) -> Result<JsValue, JsError> {
        let permissions = self
            .client
            .get_resource_permissions(&id)
            .await
            .map_err(to_js_error)?;
        to_js_value(&permissions)
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
            .map_err(to_js_error)?;
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

    /// Delete several resources.
    #[wasm_bindgen(js_name = "deleteResources")]
    pub async fn delete_resources(&self, ids: Vec<String>) -> Result<(), JsError> {
        self.client
            .delete_resources(&ids)
            .await
            .map_err(to_js_error)
    }

    // ── Favorites ────────────────────────────────────────────────────────

    /// Add a resource to the favorites; the favorite's `id` removes it.
    #[wasm_bindgen(js_name = "addFavorite")]
    pub async fn add_favorite(&self, resource_id: String) -> Result<JsValue, JsError> {
        let favorite = self
            .client
            .add_favorite(&resource_id)
            .await
            .map_err(to_js_error)?;
        to_js_value(&favorite)
    }

    /// Remove a favorite.
    #[wasm_bindgen(js_name = "removeFavorite")]
    pub async fn remove_favorite(&self, favorite_id: String) -> Result<(), JsError> {
        self.client
            .remove_favorite(&favorite_id)
            .await
            .map_err(to_js_error)
    }

    // ── Folders ──────────────────────────────────────────────────────────

    /// List all folders, or those whose name holds `search`.
    #[wasm_bindgen(js_name = "listFolders")]
    pub async fn list_folders(&self, search: Option<String>) -> Result<JsValue, JsError> {
        let query = passbolt_sdk::FolderQuery {
            search,
            ..Default::default()
        };
        let folders = self.client.get_folders(query).await.map_err(to_js_error)?;
        to_js_value(&folders)
    }

    /// Get a single folder by ID.
    #[wasm_bindgen(js_name = "getFolder")]
    pub async fn get_folder(&self, id: String) -> Result<JsValue, JsError> {
        let folder = self.client.get_folder(&id).await.map_err(to_js_error)?;
        to_js_value(&folder)
    }

    /// Create a folder, at the root or in `folderParentId`; in a parent folder it gets the
    /// parent's permissions.
    #[wasm_bindgen(js_name = "createFolder")]
    pub async fn create_folder(
        &self,
        name: String,
        folder_parent_id: Option<String>,
    ) -> Result<JsValue, JsError> {
        let folder = passbolt_sdk::folder::create::create_folder(
            &self.client,
            &name,
            folder_parent_id.as_deref(),
        )
        .await
        .map_err(to_js_error)?;
        to_js_value(&folder)
    }

    /// Rename a folder.
    #[wasm_bindgen(js_name = "renameFolder")]
    pub async fn rename_folder(&self, id: String, name: String) -> Result<JsValue, JsError> {
        let payload = passbolt_sdk::types::UpdateFolderPayload { name };
        let folder = self
            .client
            .update_folder(&id, &payload)
            .await
            .map_err(to_js_error)?;
        to_js_value(&folder)
    }

    /// Delete a folder; its content moves to the root.
    #[wasm_bindgen(js_name = "deleteFolder")]
    pub async fn delete_folder(&self, id: String) -> Result<(), JsError> {
        self.client.delete_folder(&id).await.map_err(to_js_error)
    }

    /// Delete a folder with its sub-folders and the resources the user may delete in them.
    #[wasm_bindgen(js_name = "deleteFolderWithContent")]
    pub async fn delete_folder_with_content(&self, id: String) -> Result<(), JsError> {
        self.client
            .delete_folder_with_content(&id)
            .await
            .map_err(to_js_error)
    }

    /// Get permissions for a folder.
    #[wasm_bindgen(js_name = "getFolderPermissions")]
    pub async fn get_folder_permissions(&self, id: String) -> Result<JsValue, JsError> {
        let permissions = self
            .client
            .get_folder_permissions(&id)
            .await
            .map_err(to_js_error)?;
        to_js_value(&permissions)
    }

    /// The folders as a tree: `[{ folder, children: [...] }]`, the root folders first.
    #[wasm_bindgen(js_name = "getFolderTree")]
    pub async fn get_folder_tree(&self) -> Result<JsValue, JsError> {
        let folders = self
            .client
            .get_folders(passbolt_sdk::FolderQuery::default())
            .await
            .map_err(to_js_error)?;
        to_js_value(&passbolt_sdk::build_folder_tree(&folders))
    }

    // ── Users ────────────────────────────────────────────────────────────

    /// List all users, or those matching `search`, members of `groupId`, admins with `adminOnly`.
    #[wasm_bindgen(js_name = "listUsers")]
    pub async fn list_users(
        &self,
        search: Option<String>,
        group_id: Option<String>,
        admin_only: Option<bool>,
    ) -> Result<JsValue, JsError> {
        let query = passbolt_sdk::UserQuery {
            search,
            group_ids: group_id.into_iter().collect(),
            admin_only: admin_only.unwrap_or_default(),
            ..Default::default()
        };
        let users = self.client.get_users(query).await.map_err(to_js_error)?;
        to_js_value(&users)
    }

    /// Get a user by ID.
    #[wasm_bindgen(js_name = "getUser")]
    pub async fn get_user(&self, id: String) -> Result<JsValue, JsError> {
        let user = self.client.get_user(&id).await.map_err(to_js_error)?;
        to_js_value(&user)
    }

    /// Create a user with the role named `role` (`user` or `admin`).
    #[wasm_bindgen(js_name = "createUser")]
    pub async fn create_user(
        &self,
        username: String,
        first_name: String,
        last_name: String,
        role: String,
    ) -> Result<JsValue, JsError> {
        let user = passbolt_sdk::user::create::create_user(
            &self.client,
            &username,
            &first_name,
            &last_name,
            &role,
        )
        .await
        .map_err(to_js_error)?;
        to_js_value(&user)
    }

    /// Update a user's names or role; `undefined` keeps the value.
    #[wasm_bindgen(js_name = "updateUser")]
    pub async fn update_user(
        &self,
        id: String,
        first_name: Option<String>,
        last_name: Option<String>,
        role: Option<String>,
    ) -> Result<JsValue, JsError> {
        let user = passbolt_sdk::user::update::update_user(
            &self.client,
            &id,
            first_name.as_deref(),
            last_name.as_deref(),
            role.as_deref(),
        )
        .await
        .map_err(to_js_error)?;
        to_js_value(&user)
    }

    /// Delete a user.
    #[wasm_bindgen(js_name = "deleteUser")]
    pub async fn delete_user(&self, id: String) -> Result<(), JsError> {
        self.client.delete_user(&id).await.map_err(to_js_error)
    }

    /// Preview the impact of deleting a user.
    #[wasm_bindgen(js_name = "deleteUserDryRun")]
    pub async fn delete_user_dry_run(&self, id: String) -> Result<JsValue, JsError> {
        let dry_run = self
            .client
            .delete_user_dry_run(&id)
            .await
            .map_err(to_js_error)?;
        to_js_value(&dry_run)
    }

    /// Get the currently logged-in user.
    #[wasm_bindgen(js_name = "getMe")]
    pub async fn get_me(&self) -> Result<JsValue, JsError> {
        let me = self.client.get_me().await.map_err(to_js_error)?;
        to_js_value(&me)
    }

    /// What blocks deleting the user: what they alone own or manage, as `{ resources, folders, groups,
    /// groups_to_delete }`.
    #[wasm_bindgen(js_name = "userDeleteBlockers")]
    pub async fn user_delete_blockers(&self, id: String) -> Result<JsValue, JsError> {
        let blockers = self
            .client
            .user_delete_blockers(&id)
            .await
            .map_err(to_js_error)?;
        to_js_value(&blockers)
    }

    /// Delete a user, giving what they alone own or manage to `successorId`, a user or a group that
    /// already has access to it.
    #[wasm_bindgen(js_name = "deleteUserWithTransfer")]
    pub async fn delete_user_with_transfer(
        &self,
        id: String,
        successor_id: String,
    ) -> Result<(), JsError> {
        let blockers = self
            .client
            .user_delete_blockers(&id)
            .await
            .map_err(to_js_error)?;
        if blockers.is_empty() {
            return self.client.delete_user(&id).await.map_err(to_js_error);
        }
        let transfer = blockers.transfer_to(&successor_id).map_err(to_js_error)?;
        self.client
            .delete_user_with_transfer(&id, &transfer)
            .await
            .map_err(to_js_error)
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

    /// Get a group by ID.
    #[wasm_bindgen(js_name = "getGroup")]
    pub async fn get_group(&self, id: String) -> Result<JsValue, JsError> {
        let group = self.client.get_group(&id).await.map_err(to_js_error)?;
        to_js_value(&group)
    }

    /// Create a group; a manager is also a member.
    #[wasm_bindgen(js_name = "createGroup")]
    pub async fn create_group(
        &self,
        name: String,
        member_ids: Vec<String>,
        manager_ids: Vec<String>,
    ) -> Result<JsValue, JsError> {
        let group = passbolt_sdk::group::create::create_group(
            &self.client,
            &name,
            &member_ids,
            &manager_ids,
        )
        .await
        .map_err(to_js_error)?;
        to_js_value(&group)
    }

    /// Rename a group and change its members: the removed ones first, then the added ones,
    /// who get the secrets of the group's resources. Giving a user the role they have, or
    /// removing a non-member, is an error.
    #[wasm_bindgen(js_name = "updateGroup")]
    pub async fn update_group(
        &self,
        id: String,
        name: Option<String>,
        add_member_ids: Vec<String>,
        add_manager_ids: Vec<String>,
        remove_member_ids: Vec<String>,
    ) -> Result<JsValue, JsError> {
        use passbolt_sdk::group::update::update_group;

        let adds = !add_member_ids.is_empty() || !add_manager_ids.is_empty();
        let mut name = name.as_deref();
        let mut group = None;
        if !remove_member_ids.is_empty() {
            group = Some(
                update_group(&self.client, &id, name, &remove_member_ids, &[], true)
                    .await
                    .map_err(to_js_error)?,
            );
            name = None;
        }
        if adds || group.is_none() {
            group = Some(
                update_group(
                    &self.client,
                    &id,
                    name,
                    &add_member_ids,
                    &add_manager_ids,
                    false,
                )
                .await
                .map_err(to_js_error)?,
            );
        }
        to_js_value(&group)
    }

    /// Delete a group.
    #[wasm_bindgen(js_name = "deleteGroup")]
    pub async fn delete_group(&self, id: String) -> Result<(), JsError> {
        self.client.delete_group(&id).await.map_err(to_js_error)
    }

    /// Preview the impact of deleting a group.
    #[wasm_bindgen(js_name = "deleteGroupDryRun")]
    pub async fn delete_group_dry_run(&self, id: String) -> Result<JsValue, JsError> {
        let dry_run = self
            .client
            .delete_group_dry_run(&id)
            .await
            .map_err(to_js_error)?;
        to_js_value(&dry_run)
    }

    /// What blocks deleting the group: what it alone owns, as `{ resources, folders, groups,
    /// groups_to_delete }`.
    #[wasm_bindgen(js_name = "groupDeleteBlockers")]
    pub async fn group_delete_blockers(&self, id: String) -> Result<JsValue, JsError> {
        let blockers = self
            .client
            .group_delete_blockers(&id)
            .await
            .map_err(to_js_error)?;
        to_js_value(&blockers)
    }

    /// Delete a group, giving what it alone owns to `successorId`, a user or a group that
    /// already has access to it.
    #[wasm_bindgen(js_name = "deleteGroupWithTransfer")]
    pub async fn delete_group_with_transfer(
        &self,
        id: String,
        successor_id: String,
    ) -> Result<(), JsError> {
        let blockers = self
            .client
            .group_delete_blockers(&id)
            .await
            .map_err(to_js_error)?;
        if blockers.is_empty() {
            return self.client.delete_group(&id).await.map_err(to_js_error);
        }
        let transfer = blockers.transfer_to(&successor_id).map_err(to_js_error)?;
        self.client
            .delete_group_with_transfer(&id, &transfer)
            .await
            .map_err(to_js_error)
    }

    // ── Tags ─────────────────────────────────────────────────────────────

    /// List all tags.
    #[wasm_bindgen(js_name = "getTags")]
    pub async fn get_tags(&self) -> Result<JsValue, JsError> {
        let tags = self.client.get_tags().await.map_err(to_js_error)?;
        to_js_value(&tags)
    }

    /// Add a tag to a resource, keeping its other tags; returns the resource's tags.
    #[wasm_bindgen(js_name = "addTagToResource")]
    pub async fn add_tag_to_resource(
        &self,
        resource_id: String,
        slug: String,
    ) -> Result<JsValue, JsError> {
        let tags = self
            .client
            .add_tag_to_resource(&resource_id, &slug)
            .await
            .map_err(to_js_error)?;
        to_js_value(&tags)
    }

    /// Replace all the tags of a resource; returns its tags.
    #[wasm_bindgen(js_name = "setResourceTags")]
    pub async fn set_resource_tags(
        &self,
        resource_id: String,
        slugs: Vec<String>,
    ) -> Result<JsValue, JsError> {
        let tags = self
            .client
            .update_resource_tags(&resource_id, &slugs)
            .await
            .map_err(to_js_error)?;
        to_js_value(&tags)
    }

    /// Rename a tag.
    #[wasm_bindgen(js_name = "renameTag")]
    pub async fn rename_tag(&self, id: String, slug: String) -> Result<JsValue, JsError> {
        let tag = self
            .client
            .update_tag(&id, &slug)
            .await
            .map_err(to_js_error)?;
        to_js_value(&tag)
    }

    /// Delete a tag.
    #[wasm_bindgen(js_name = "deleteTag")]
    pub async fn delete_tag(&self, id: String) -> Result<(), JsError> {
        self.client.delete_tag(&id).await.map_err(to_js_error)
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

    /// Delete a comment.
    #[wasm_bindgen(js_name = "deleteComment")]
    pub async fn delete_comment(&self, id: String) -> Result<(), JsError> {
        self.client.delete_comment(&id).await.map_err(to_js_error)
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

    // ── Password expiry ──────────────────────────────────────────────────

    /// The password expiry settings: `{ id, default_expiry_period, policy_override,
    /// automatic_expiry, automatic_update }`, the period in days.
    #[wasm_bindgen(js_name = "getPasswordExpirySettings")]
    pub async fn get_password_expiry_settings(&self) -> Result<JsValue, JsError> {
        let settings = self
            .client
            .get_password_expiry_settings()
            .await
            .map_err(to_js_error)?;
        to_js_value(&settings)
    }

    /// Create or update the password expiry settings (admin).
    #[wasm_bindgen(js_name = "savePasswordExpirySettings")]
    pub async fn save_password_expiry_settings(
        &self,
        settings: JsValue,
    ) -> Result<JsValue, JsError> {
        let settings: passbolt_sdk::types::PasswordExpirySettings =
            serde_wasm_bindgen::from_value(settings)
                .map_err(|error| JsError::new(&format!("Invalid settings: {error}")))?;
        let saved = self
            .client
            .save_password_expiry_settings(&settings)
            .await
            .map_err(to_js_error)?;
        to_js_value(&saved)
    }

    /// Delete the password expiry settings (admin): the defaults apply again.
    #[wasm_bindgen(js_name = "deletePasswordExpirySettings")]
    pub async fn delete_password_expiry_settings(&self, id: String) -> Result<(), JsError> {
        self.client
            .delete_password_expiry_settings(&id)
            .await
            .map_err(to_js_error)
    }

    // ── Resource types and metadata settings ─────────────────────────────

    /// The resource types of the server, with the JSON Schemas of their `definition`.
    #[wasm_bindgen(js_name = "listResourceTypes")]
    pub async fn list_resource_types(&self) -> Result<JsValue, JsError> {
        let resource_types = self.client.resource_types().await.map_err(to_js_error)?;
        to_js_value(&*resource_types)
    }

    /// Which metadata versions the organization creates and allows.
    #[wasm_bindgen(js_name = "getMetadataTypesSettings")]
    pub async fn get_metadata_types_settings(&self) -> Result<JsValue, JsError> {
        let settings = self
            .client
            .get_metadata_types_settings()
            .await
            .map_err(to_js_error)?;
        to_js_value(&settings)
    }

    /// Save the metadata types settings (admin).
    #[wasm_bindgen(js_name = "saveMetadataTypesSettings")]
    pub async fn save_metadata_types_settings(
        &self,
        settings: JsValue,
    ) -> Result<JsValue, JsError> {
        let settings: passbolt_sdk::types::MetadataTypesSettings =
            serde_wasm_bindgen::from_value(settings)
                .map_err(|error| JsError::new(&format!("Invalid settings: {error}")))?;
        let saved = self
            .client
            .save_metadata_types_settings(&settings)
            .await
            .map_err(to_js_error)?;
        to_js_value(&saved)
    }

    /// How metadata keys are used: `{ allow_usage_of_personal_keys, zero_knowledge_key_share }`.
    #[wasm_bindgen(js_name = "getMetadataKeysSettings")]
    pub async fn get_metadata_keys_settings(&self) -> Result<JsValue, JsError> {
        let settings = self
            .client
            .get_metadata_keys_settings()
            .await
            .map_err(to_js_error)?;
        to_js_value(&settings)
    }

    /// Save the metadata keys settings (admin).
    #[wasm_bindgen(js_name = "saveMetadataKeysSettings")]
    pub async fn save_metadata_keys_settings(&self, settings: JsValue) -> Result<JsValue, JsError> {
        let settings: passbolt_sdk::types::MetadataKeysSettings =
            serde_wasm_bindgen::from_value(settings)
                .map_err(|error| JsError::new(&format!("Invalid settings: {error}")))?;
        let saved = self
            .client
            .save_metadata_keys_settings(&settings)
            .await
            .map_err(to_js_error)?;
        to_js_value(&saved)
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
            String::new(),
            String::new(),
        );

        assert_eq!(config.server_url, "https://passbolt.test");
        assert_eq!(config.private_key_armored, "armored key");
        assert_eq!(config.passphrase.expose_secret(), "secret passphrase");
        assert_eq!(config.mfa_mode, "");
        assert!(!config.tls_skip_verify);
        assert_eq!(config.proxy, "");
    }

    #[test]
    fn test_build_sdk_config_carries_the_pinned_keys() {
        let config = build_sdk_config(
            "https://passbolt.test".into(),
            "armored key".into(),
            "secret passphrase".into(),
            SERVER_PUBLIC.into(),
            "ABCD".into(),
        );

        assert_eq!(config.server_public_key, SERVER_PUBLIC);
        assert_eq!(config.metadata_key_fingerprint, "ABCD");
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
    const SERVER_PUBLIC: &str =
        include_str!("../../passbolt-sdk/tests/fixtures/keys/server_public.asc");
    const BETTY_PUBLIC: &str =
        include_str!("../../passbolt-sdk/tests/fixtures/keys/betty_public.asc");

    const ADA_PRIVATE: &str =
        include_str!("../../passbolt-sdk/tests/fixtures/keys/ada_private.asc");
    const ADA_PUBLIC: &str = include_str!("../../passbolt-sdk/tests/fixtures/keys/ada_public.asc");
    const ADA_ID: &str = "8b6c3a10-0000-4000-8000-00000000a0da";

    /// A `fetch` answering the `GPGAuth` login with `challenge`, and `/users/me.json`.
    fn passbolt_fetch(challenge: &str) -> JsValue {
        let factory = js_sys::Function::new_with_args(
            "challenge, userId, armoredKey, fingerprint, serverKey, serverFingerprint",
            r#"
            const json = (body, headers = {}) =>
                new Response(JSON.stringify({ header: { status: "success" }, body }), {
                    headers: { "X-GPGAuth-Version": "1.3.0", ...headers },
                });
            const step = (authenticated, progress, headers) => ({
                "X-GPGAuth-Authenticated": authenticated,
                "X-GPGAuth-Progress": progress,
                ...headers,
            });
            return async (request) => {
                const body = request.method === "POST" ? await request.text() : "";
                if (request.url.endsWith("/auth/login.json")) {
                    return body.includes("user_token_result")
                        ? json({ user: { id: userId } }, step("true", "complete", { "X-GPGAuth-Refer": "/" }))
                        : json(
                              null,
                              step("false", "stage1", {
                                  "X-GPGAuth-User-Auth-Token": encodeURIComponent(challenge),
                              }),
                          );
                }
                if (request.url.endsWith("/auth/verify.json")) {
                    // Holds no private key: it cannot answer the pinned key's challenge.
                    return request.method === "GET"
                        ? json({ fingerprint: serverFingerprint, keydata: serverKey })
                        : new Response("{}", { status: 400 });
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
        let server_fingerprint =
            passbolt_sdk::crypto::public_key_fingerprint(SERVER_PUBLIC).unwrap();
        let arguments: js_sys::Array = [
            challenge,
            ADA_ID,
            ADA_PUBLIC,
            &get_key_fingerprint(ADA_PRIVATE).unwrap(),
            SERVER_PUBLIC,
            &server_fingerprint,
        ]
        .into_iter()
        .map(JsValue::from_str)
        .collect();
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
            Some(options.unchecked_into()),
        )
        .await;

        js_sys::Reflect::set(&global, &"fetch".into(), &real_fetch).unwrap();
        crate::http::set_csrf_token_provider(None);
        if let Err(error) = session {
            let error = JsValue::from(error);
            panic!("{:?}", js_sys::Reflect::get(&error, &"message".into()));
        }
    }

    /// Run `test` with `fetch` answering as [`passbolt_fetch`] does.
    async fn with_passbolt_fetch<T>(test: impl std::future::Future<Output = T>) -> T {
        let token = format!("gpgauthv1.3.0|36|{}|gpgauthv1.3.0", uuid::Uuid::new_v4());
        let challenge = encrypt_message(token.as_bytes(), vec![ADA_PUBLIC.into()]).unwrap();
        let global = js_sys::global();
        let real_fetch = js_sys::Reflect::get(&global, &"fetch".into()).unwrap();
        js_sys::Reflect::set(&global, &"fetch".into(), &passbolt_fetch(&challenge)).unwrap();
        let result = test.await;
        js_sys::Reflect::set(&global, &"fetch".into(), &real_fetch).unwrap();
        result
    }

    #[wasm_bindgen_test]
    async fn test_fetch_server_key_gives_the_key_and_its_fingerprint() {
        let server_key = with_passbolt_fetch(PassboltSession::fetch_server_key(
            "http://127.0.0.1:1".into(),
        ))
        .await
        .ok()
        .unwrap();

        let armored_key = js_sys::Reflect::get(&server_key, &"armoredKey".into()).unwrap();
        let fingerprint = js_sys::Reflect::get(&server_key, &"fingerprint".into()).unwrap();
        assert_eq!(armored_key.as_string().as_deref(), Some(SERVER_PUBLIC));
        assert_eq!(
            fingerprint.as_string(),
            passbolt_sdk::crypto::public_key_fingerprint(SERVER_PUBLIC).ok()
        );
    }

    #[wasm_bindgen_test]
    async fn test_login_refuses_a_server_without_the_pinned_key() {
        let options = js_sys::Object::new();
        js_sys::Reflect::set(&options, &"serverPublicKey".into(), &SERVER_PUBLIC.into()).unwrap();

        let session = with_passbolt_fetch(PassboltSession::login(
            "http://127.0.0.1:1".into(),
            ADA_PRIVATE.into(),
            "ada-passphrase".into(),
            Some(options.unchecked_into()),
        ))
        .await;

        let Err(error) = session else {
            panic!("logged in to a server without the pinned key")
        };
        let message = js_sys::Reflect::get(&JsValue::from(error), &"message".into()).unwrap();
        assert!(
            message.as_string().unwrap_or_default().contains("identity"),
            "{message:?}"
        );
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
