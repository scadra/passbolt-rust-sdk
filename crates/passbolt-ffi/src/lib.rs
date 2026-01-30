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

// UniFFI requires owned types at the FFI boundary (no &str, &[u8] across FFI).
// Sync block_on wrappers are intentional; consumers dispatch from background threads.
#![allow(clippy::future_not_send, clippy::needless_pass_by_value)]

//! Passbolt SDK — Multi-language FFI bindings via `UniFFI`.
//!
//! Generates native bindings for Python, Kotlin (Android), Swift (iOS),
//! C#, and Ruby from a single Rust crate.
//!
//! ## Quick start (Python)
//! ```python
//! from passbolt_ffi import PassboltClient
//!
//! client = PassboltClient.login("https://passbolt.example.com", private_key, passphrase)
//! resources = client.list_resources(None, False, False)
//! client.logout()
//! ```

mod error;
mod mfa;
mod types;

pub use error::PassboltFfiError;

uniffi::setup_scaffolding!();

use std::sync::{Arc, LazyLock};

use passbolt_sdk::config::SdkConfig;
use passbolt_sdk::platform::native::{NativeHttpClient, NativeHttpConfig};
use passbolt_sdk::{MfaProvider, PassboltSdk};

use crate::mfa::{totp_provider, NON_INTERACTIVE_TOTP};
use crate::types::{
    FfiAro, FfiComment, FfiFavorite, FfiFolder, FfiFolderQuery, FfiFolderTreeNode, FfiGroup,
    FfiGroupDeleteDryRun, FfiPasswordExpirySettings, FfiPermission, FfiResource, FfiResourceQuery,
    FfiSecretData, FfiTag, FfiUser, FfiUserDeleteDryRun, FfiUserQuery,
};

type Client = PassboltSdk<NativeHttpClient>;

/// Global tokio runtime for executing async SDK operations.
static RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("Failed to create tokio runtime")
});

const MFA_RETRY_COUNT: u32 = 3;

fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|text| !text.trim().is_empty())
}

/// A request waits this long by default before failing, instead of blocking the caller forever.
const DEFAULT_TIMEOUT_SECONDS: u64 = 60;

fn build_http_config(options: &FfiLoginOptions) -> NativeHttpConfig {
    NativeHttpConfig {
        tls_skip_verify: options.tls_skip_verify,
        client_cert_pem: non_empty(options.client_certificate_pem.clone()).map(String::into_bytes),
        client_key_pem: non_empty(options.client_key_pem.clone()).map(String::into_bytes),
        proxy_url: non_empty(options.proxy.clone()),
        resolve: Vec::new(),
        timeout: match options.timeout_seconds.unwrap_or(DEFAULT_TIMEOUT_SECONDS) {
            0 => None,
            seconds => Some(std::time::Duration::from_secs(seconds)),
        },
    }
}

/// How to log in, beyond the credentials.
#[derive(uniffi::Record, Default)]
pub struct FfiLoginOptions {
    pub tls_skip_verify: bool,
    pub proxy: Option<String>,
    /// The base32 TOTP secret answering the MFA challenge without prompting.
    pub mfa_totp_token: Option<String>,
    /// The armored server public key pinned with [`fetch_server_key`]: each login then checks
    /// the server holds its private key.
    pub server_public_key: Option<String>,
    /// The shared metadata key fingerprint pinned with
    /// [`PassboltClient::metadata_key_fingerprint`]: shared metadata is then only encrypted
    /// for that key.
    pub metadata_key_fingerprint: Option<String>,
    /// Seconds a request may take; `None` is 60, `0` waits forever.
    pub timeout_seconds: Option<u64>,
    /// PEM certificate and private key, for a server asking for a client certificate (mTLS).
    pub client_certificate_pem: Option<String>,
    pub client_key_pem: Option<String>,
}

/// The server public key, to pin.
#[derive(uniffi::Record)]
pub struct FfiServerKey {
    /// Computed from the key, checked against the one the server announces.
    pub fingerprint: String,
    pub armored_key: String,
}

/// An empty or blank `mfa_totp_token` means no non-interactive MFA.
fn build_sdk_config(
    server_url: String,
    private_key_armored: String,
    passphrase: String,
    options: FfiLoginOptions,
) -> SdkConfig {
    let FfiLoginOptions {
        tls_skip_verify,
        proxy,
        mfa_totp_token,
        server_public_key,
        metadata_key_fingerprint,
        ..
    } = options;
    let mfa_totp_token = non_empty(mfa_totp_token);
    SdkConfig {
        server_url,
        private_key_armored,
        passphrase: secrecy::SecretString::from(passphrase),
        mfa_mode: if mfa_totp_token.is_some() {
            NON_INTERACTIVE_TOTP.into()
        } else {
            String::new()
        },
        mfa_totp_token: mfa_totp_token.unwrap_or_default(),
        mfa_totp_offset: 0,
        mfa_retrys: MFA_RETRY_COUNT,
        tls_skip_verify,
        tls_client_cert: String::new(),
        tls_client_private_key: String::new(),
        proxy: non_empty(proxy).unwrap_or_default(),
        server_public_key: non_empty(server_public_key).unwrap_or_default(),
        metadata_key_fingerprint: non_empty(metadata_key_fingerprint).unwrap_or_default(),
        server_verify_enc_token: String::new(),
        server_verify_token: String::new(),
    }
}

// ── PassboltClient ──────────────────────────────────────────────────────────

/// Authenticated Passbolt client for CRUD operations.
///
/// All methods are synchronous at the FFI boundary; they block internally
/// on the tokio runtime. Call from background threads on mobile platforms.
#[derive(uniffi::Object)]
pub struct PassboltClient {
    inner: Client,
}

#[uniffi::export]
impl PassboltClient {
    // ── Auth ────────────────────────────────────────────────────────────

    /// Authenticate against a Passbolt server and return a client session.
    #[uniffi::constructor]
    pub fn login(
        server_url: String,
        private_key_armored: String,
        passphrase: String,
    ) -> Result<Arc<Self>, PassboltFfiError> {
        Self::login_with_options(
            server_url,
            private_key_armored,
            passphrase,
            false,
            None,
            None,
        )
    }

    /// Authenticate with advanced TLS/proxy options.
    ///
    /// `mfa_totp_token` is the base32 TOTP secret used to answer the MFA
    /// challenge without prompting; `None` or an empty string disables it.
    #[uniffi::constructor]
    pub fn login_with_options(
        server_url: String,
        private_key_armored: String,
        passphrase: String,
        tls_skip_verify: bool,
        proxy: Option<String>,
        mfa_totp_token: Option<String>,
    ) -> Result<Arc<Self>, PassboltFfiError> {
        Self::login_with_config(
            server_url,
            private_key_armored,
            passphrase,
            FfiLoginOptions {
                tls_skip_verify,
                proxy,
                mfa_totp_token,
                ..FfiLoginOptions::default()
            },
        )
    }

    /// Authenticate with `options`, the pinned server and metadata keys among them.
    #[uniffi::constructor]
    pub fn login_with_config(
        server_url: String,
        private_key_armored: String,
        passphrase: String,
        options: FfiLoginOptions,
    ) -> Result<Arc<Self>, PassboltFfiError> {
        let http_config = build_http_config(&options);
        let config = build_sdk_config(server_url, private_key_armored, passphrase, options);
        let mfa_provider = totp_provider(&config).map_err(|error| PassboltFfiError::Config {
            message: error.to_string(),
        })?;
        RUNTIME.block_on(async {
            let http =
                NativeHttpClient::new(&http_config).map_err(|error| PassboltFfiError::Config {
                    message: error.to_string(),
                })?;

            let client = Client::login(
                http,
                &config,
                mfa_provider.map(|provider| Box::new(provider) as Box<dyn MfaProvider>),
                config.mfa_retrys,
            )
            .await
            .map_err(PassboltFfiError::from)?;

            Ok(Arc::new(Self { inner: client }))
        })
    }

    /// Terminate the server-side session.
    pub fn logout(&self) {
        RUNTIME.block_on(self.inner.logout());
    }

    /// Check if the session is still valid.
    pub fn check_auth(&self) -> Result<bool, PassboltFfiError> {
        RUNTIME
            .block_on(self.inner.check_auth_status())
            .map_err(Into::into)
    }

    // ── Resources ───────────────────────────────────────────────────────

    /// List resources with optional search and filters.
    pub fn list_resources(
        &self,
        search: Option<String>,
        favorites_only: bool,
        owned_by_me: bool,
    ) -> Result<Vec<FfiResource>, PassboltFfiError> {
        let query = FfiResourceQuery {
            search,
            favorites_only,
            owned_by_me,
        };
        let resources = RUNTIME
            .block_on(self.inner.get_resources(query.into()))
            .map_err(PassboltFfiError::from)?;
        Ok(resources.into_iter().map(FfiResource::from).collect())
    }

    /// A resource with its v5 metadata and its secret decrypted, for every resource type, as
    /// JSON: `name`, `username`, `uris`, `description`, `password`, `metadata`, `secret`…
    pub fn get_resource_view(&self, id: String) -> Result<String, PassboltFfiError> {
        let view = RUNTIME
            .block_on(passbolt_sdk::resource::get::get_resource_view(
                &self.inner,
                &id,
            ))
            .map_err(|error| PassboltFfiError::Other {
                message: format!("{error:#}"),
            })?;
        to_json(&view)
    }

    /// Resources with their v5 metadata decrypted, searched by their decrypted name, as a JSON
    /// array; their secrets too with `with_secrets`. One that does not decrypt has an `error`.
    pub fn list_resource_views(
        &self,
        search: Option<String>,
        with_secrets: bool,
    ) -> Result<String, PassboltFfiError> {
        let query = passbolt_sdk::ResourceQuery {
            search,
            ..Default::default()
        };
        let views = RUNTIME
            .block_on(passbolt_sdk::resource::list::list_resources(
                &self.inner,
                query,
                &[],
                with_secrets.then_some(0),
            ))
            .map_err(PassboltFfiError::from)?;
        to_json(&views)
    }

    /// Create a resource of any type from JSON: `{"name": …, "resource_type"?, "username"?,
    /// "uris"?, "password"?, "totp"?, "note"?, "pin_code"?, "custom_fields"?,
    /// "metadata_fields"?, "secret_fields"?, …}`. Returns the created resource.
    pub fn create_resource(
        &self,
        new_resource_json: String,
    ) -> Result<FfiResource, PassboltFfiError> {
        let new_resource = from_json(&new_resource_json)?;
        let resource = RUNTIME
            .block_on(passbolt_sdk::resource::create::create_resource(
                &self.inner,
                &new_resource,
            ))
            .map_err(PassboltFfiError::from)?;
        Ok(FfiResource::from(resource))
    }

    /// Update a resource from the JSON of the fields to change; `"expired": null` clears the
    /// expiry. Other fields keep their value.
    pub fn update_resource(
        &self,
        id: String,
        changes_json: String,
    ) -> Result<FfiResource, PassboltFfiError> {
        let changes = from_json(&changes_json)?;
        let resource = RUNTIME
            .block_on(passbolt_sdk::resource::update::update_resource(
                &self.inner,
                &id,
                &changes,
            ))
            .map_err(PassboltFfiError::from)?;
        Ok(FfiResource::from(resource))
    }

    /// Share a resource with users and groups (`permission_type` 1, 7 or 15), or revoke with -1.
    pub fn share_resource(
        &self,
        id: String,
        user_ids: Vec<String>,
        group_ids: Vec<String>,
        permission_type: i32,
    ) -> Result<(), PassboltFfiError> {
        RUNTIME
            .block_on(passbolt_sdk::resource::share::share_resource(
                &self.inner,
                &id,
                &user_ids,
                &group_ids,
                permission_type,
            ))
            .map_err(Into::into)
    }

    /// Share a folder, and with `with_content` the sub-folders and resources the user owns.
    pub fn share_folder(
        &self,
        id: String,
        user_ids: Vec<String>,
        group_ids: Vec<String>,
        permission_type: i32,
        with_content: bool,
    ) -> Result<(), PassboltFfiError> {
        RUNTIME
            .block_on(passbolt_sdk::folder::share::share_folder(
                &self.inner,
                &id,
                &user_ids,
                &group_ids,
                permission_type,
                with_content,
            ))
            .map_err(Into::into)
    }

    /// Move a resource into a folder, or to the root without one.
    pub fn move_resource(
        &self,
        id: String,
        folder_id: Option<String>,
    ) -> Result<(), PassboltFfiError> {
        RUNTIME
            .block_on(self.inner.move_resource(&id, folder_id.as_deref()))
            .map_err(Into::into)
    }

    /// Move a folder into another one, or to the root without one.
    pub fn move_folder(
        &self,
        id: String,
        folder_id: Option<String>,
    ) -> Result<(), PassboltFfiError> {
        RUNTIME
            .block_on(self.inner.move_folder(&id, folder_id.as_deref()))
            .map_err(Into::into)
    }

    /// Get a single resource by ID.
    pub fn get_resource(&self, id: String) -> Result<FfiResource, PassboltFfiError> {
        let resource = RUNTIME
            .block_on(self.inner.get_resource(&id))
            .map_err(PassboltFfiError::from)?;
        Ok(FfiResource::from(resource))
    }

    /// Get multiple resources by IDs.
    pub fn get_resources_by_ids(
        &self,
        ids: Vec<String>,
    ) -> Result<Vec<FfiResource>, PassboltFfiError> {
        let resources = RUNTIME
            .block_on(self.inner.get_resources_by_ids(&ids))
            .map_err(PassboltFfiError::from)?;
        Ok(resources.into_iter().map(FfiResource::from).collect())
    }

    /// Decrypt a resource's secret. Pass the resource obtained from `get_resource`.
    pub fn decrypt_resource_secret(
        &self,
        resource_id: String,
    ) -> Result<FfiSecretData, PassboltFfiError> {
        RUNTIME.block_on(async {
            let resource = self
                .inner
                .get_resource(&resource_id)
                .await
                .map_err(PassboltFfiError::from)?;
            let secret = self
                .inner
                .decrypt_resource_secret(&resource)
                .await
                .map_err(PassboltFfiError::from)?;
            Ok(FfiSecretData::from(secret))
        })
    }

    /// Delete a resource.
    pub fn delete_resource(&self, id: String) -> Result<(), PassboltFfiError> {
        RUNTIME
            .block_on(self.inner.delete_resource(&id))
            .map_err(Into::into)
    }

    /// Bulk delete resources.
    pub fn delete_resources(&self, ids: Vec<String>) -> Result<(), PassboltFfiError> {
        RUNTIME
            .block_on(self.inner.delete_resources(&ids))
            .map_err(Into::into)
    }

    /// Get permissions for a resource.
    pub fn get_resource_permissions(
        &self,
        id: String,
    ) -> Result<Vec<FfiPermission>, PassboltFfiError> {
        let permissions = RUNTIME
            .block_on(self.inner.get_resource_permissions(&id))
            .map_err(PassboltFfiError::from)?;
        Ok(permissions.into_iter().map(FfiPermission::from).collect())
    }

    // ── Folders ─────────────────────────────────────────────────────────

    /// List all folders.
    pub fn list_folders(&self, search: Option<String>) -> Result<Vec<FfiFolder>, PassboltFfiError> {
        let query = FfiFolderQuery { search };
        let folders = RUNTIME
            .block_on(self.inner.get_folders(query.into()))
            .map_err(PassboltFfiError::from)?;
        Ok(folders.into_iter().map(FfiFolder::from).collect())
    }

    /// Get a single folder by ID.
    pub fn get_folder(&self, id: String) -> Result<FfiFolder, PassboltFfiError> {
        let folder = RUNTIME
            .block_on(self.inner.get_folder(&id))
            .map_err(PassboltFfiError::from)?;
        Ok(FfiFolder::from(folder))
    }

    /// Delete a folder.
    pub fn delete_folder(&self, id: String) -> Result<(), PassboltFfiError> {
        RUNTIME
            .block_on(self.inner.delete_folder(&id))
            .map_err(Into::into)
    }

    /// Build a folder tree from the flat folder list.
    pub fn get_folder_tree(&self) -> Result<Vec<FfiFolderTreeNode>, PassboltFfiError> {
        let folders = RUNTIME
            .block_on(self.inner.get_folders(passbolt_sdk::FolderQuery::default()))
            .map_err(PassboltFfiError::from)?;
        let tree = passbolt_sdk::build_folder_tree(&folders);
        Ok(tree.into_iter().map(FfiFolderTreeNode::from).collect())
    }

    // ── Users ───────────────────────────────────────────────────────────

    /// List all users.
    pub fn list_users(
        &self,
        search: Option<String>,
        group_id: Option<String>,
        admin_only: bool,
    ) -> Result<Vec<FfiUser>, PassboltFfiError> {
        let query = FfiUserQuery {
            search,
            group_id,
            admin_only,
        };
        let users = RUNTIME
            .block_on(self.inner.get_users(query.into()))
            .map_err(PassboltFfiError::from)?;
        Ok(users.into_iter().map(FfiUser::from).collect())
    }

    /// Get the currently logged-in user.
    pub fn get_me(&self) -> Result<FfiUser, PassboltFfiError> {
        let user = RUNTIME
            .block_on(self.inner.get_me())
            .map_err(PassboltFfiError::from)?;
        Ok(FfiUser::from(user))
    }

    /// Get a user by ID.
    pub fn get_user(&self, id: String) -> Result<FfiUser, PassboltFfiError> {
        let user = RUNTIME
            .block_on(self.inner.get_user(&id))
            .map_err(PassboltFfiError::from)?;
        Ok(FfiUser::from(user))
    }

    /// Delete a user.
    pub fn delete_user(&self, id: String) -> Result<(), PassboltFfiError> {
        RUNTIME
            .block_on(self.inner.delete_user(&id))
            .map_err(Into::into)
    }

    /// Preview the impact of deleting a user.
    pub fn delete_user_dry_run(&self, id: String) -> Result<FfiUserDeleteDryRun, PassboltFfiError> {
        let result = RUNTIME
            .block_on(self.inner.delete_user_dry_run(&id))
            .map_err(PassboltFfiError::from)?;
        Ok(FfiUserDeleteDryRun::from(result))
    }

    // ── Groups ──────────────────────────────────────────────────────────

    /// List all groups.
    pub fn list_groups(&self) -> Result<Vec<FfiGroup>, PassboltFfiError> {
        let groups = RUNTIME
            .block_on(self.inner.get_groups(passbolt_sdk::GroupQuery::default()))
            .map_err(PassboltFfiError::from)?;
        Ok(groups.into_iter().map(FfiGroup::from).collect())
    }

    /// Get a group by ID.
    pub fn get_group(&self, id: String) -> Result<FfiGroup, PassboltFfiError> {
        let group = RUNTIME
            .block_on(self.inner.get_group(&id))
            .map_err(PassboltFfiError::from)?;
        Ok(FfiGroup::from(group))
    }

    /// Delete a group.
    pub fn delete_group(&self, id: String) -> Result<(), PassboltFfiError> {
        RUNTIME
            .block_on(self.inner.delete_group(&id))
            .map_err(Into::into)
    }

    /// Preview the impact of deleting a group.
    pub fn delete_group_dry_run(
        &self,
        id: String,
    ) -> Result<FfiGroupDeleteDryRun, PassboltFfiError> {
        let result = RUNTIME
            .block_on(self.inner.delete_group_dry_run(&id))
            .map_err(PassboltFfiError::from)?;
        Ok(FfiGroupDeleteDryRun::from(result))
    }

    // ── Tags ────────────────────────────────────────────────────────────

    /// List all tags.
    pub fn get_tags(&self) -> Result<Vec<FfiTag>, PassboltFfiError> {
        let tags = RUNTIME
            .block_on(self.inner.get_tags())
            .map_err(PassboltFfiError::from)?;
        Ok(tags.into_iter().map(FfiTag::from).collect())
    }

    /// Add a tag to a resource, keeping its other tags; returns the resource's tags.
    pub fn add_tag_to_resource(
        &self,
        resource_id: String,
        slug: String,
    ) -> Result<Vec<FfiTag>, PassboltFfiError> {
        let tags = RUNTIME
            .block_on(self.inner.add_tag_to_resource(&resource_id, &slug))
            .map_err(PassboltFfiError::from)?;
        Ok(tags.into_iter().map(FfiTag::from).collect())
    }

    /// Delete a tag.
    pub fn delete_tag(&self, id: String) -> Result<(), PassboltFfiError> {
        RUNTIME
            .block_on(self.inner.delete_tag(&id))
            .map_err(Into::into)
    }

    // ── Comments ────────────────────────────────────────────────────────

    /// Get comments for a resource.
    pub fn get_comments(&self, resource_id: String) -> Result<Vec<FfiComment>, PassboltFfiError> {
        let comments = RUNTIME
            .block_on(self.inner.get_comments(&resource_id))
            .map_err(PassboltFfiError::from)?;
        Ok(comments.into_iter().map(FfiComment::from).collect())
    }

    /// Create a comment on a resource.
    pub fn create_comment(
        &self,
        resource_id: String,
        content: String,
        parent_id: Option<String>,
    ) -> Result<FfiComment, PassboltFfiError> {
        let comment = RUNTIME
            .block_on(
                self.inner
                    .create_comment(&resource_id, &content, parent_id.as_deref()),
            )
            .map_err(PassboltFfiError::from)?;
        Ok(FfiComment::from(comment))
    }

    /// Delete a comment.
    pub fn delete_comment(&self, id: String) -> Result<(), PassboltFfiError> {
        RUNTIME
            .block_on(self.inner.delete_comment(&id))
            .map_err(Into::into)
    }

    // ── Sharing ─────────────────────────────────────────────────────────

    /// Search for users and groups (AROs) for sharing.
    pub fn search_aros(&self, search: String) -> Result<Vec<FfiAro>, PassboltFfiError> {
        let aros = RUNTIME
            .block_on(self.inner.search_aros(&search))
            .map_err(PassboltFfiError::from)?;
        Ok(aros.into_iter().map(FfiAro::from).collect())
    }

    // ── Favorites ───────────────────────────────────────────────────────

    /// Add a resource to favorites.
    pub fn add_favorite(&self, resource_id: String) -> Result<FfiFavorite, PassboltFfiError> {
        let favorite = RUNTIME
            .block_on(self.inner.add_favorite(&resource_id))
            .map_err(PassboltFfiError::from)?;
        Ok(FfiFavorite::from(favorite))
    }

    /// Remove a favorite.
    pub fn remove_favorite(&self, favorite_id: String) -> Result<(), PassboltFfiError> {
        RUNTIME
            .block_on(self.inner.remove_favorite(&favorite_id))
            .map_err(Into::into)
    }

    // ── Password Expiry ─────────────────────────────────────────────────

    /// Get password expiry settings.
    pub fn get_password_expiry_settings(
        &self,
    ) -> Result<FfiPasswordExpirySettings, PassboltFfiError> {
        let settings = RUNTIME
            .block_on(self.inner.get_password_expiry_settings())
            .map_err(PassboltFfiError::from)?;
        Ok(FfiPasswordExpirySettings::from(settings))
    }

    // ── HIBP ────────────────────────────────────────────────────────────

    /// Check if a password has been exposed in data breaches.
    /// Returns the number of times found (0 = not breached).
    pub fn check_password_pwned(&self, password: String) -> Result<u64, PassboltFfiError> {
        RUNTIME
            .block_on(self.inner.check_password_pwned(&password))
            .map_err(Into::into)
    }

    // ── Session info ────────────────────────────────────────────────────

    /// Get the current user's ID.
    pub fn user_id(&self) -> String {
        self.inner.user_id.clone()
    }

    /// Get the server base URL.
    pub fn base_url(&self) -> String {
        self.inner.base_url.clone()
    }

    /// Keep the session alive, as the browser extension does every few minutes.
    pub fn keep_alive(&self) -> Result<(), PassboltFfiError> {
        RUNTIME
            .block_on(self.inner.keep_alive())
            .map_err(Into::into)
    }

    /// The fingerprint of the active shared metadata key, to pin in
    /// [`FfiLoginOptions::metadata_key_fingerprint`]; `None` without one.
    pub fn metadata_key_fingerprint(&self) -> Result<Option<String>, PassboltFfiError> {
        let metadata_keys = RUNTIME
            .block_on(self.inner.metadata_keys())
            .map_err(PassboltFfiError::from)?;
        Ok(metadata_keys.active_fingerprint())
    }
}

/// The server public key, to pin in [`FfiLoginOptions::server_public_key`] once the user
/// confirmed its fingerprint.
#[uniffi::export]
pub fn fetch_server_key(
    server_url: String,
    tls_skip_verify: bool,
) -> Result<FfiServerKey, PassboltFfiError> {
    let http_config = build_http_config(&FfiLoginOptions {
        tls_skip_verify,
        ..FfiLoginOptions::default()
    });
    RUNTIME.block_on(async {
        let http =
            NativeHttpClient::new(&http_config).map_err(|error| PassboltFfiError::Config {
                message: error.to_string(),
            })?;
        let (fingerprint, armored_key) =
            passbolt_sdk::auth::fetch_server_key(&http, server_url.trim_end_matches('/'))
                .await
                .map_err(PassboltFfiError::from)?;
        Ok(FfiServerKey {
            fingerprint,
            armored_key,
        })
    })
}

// ── Stateless crypto functions ──────────────────────────────────────────────

/// Decrypt a PGP-armored message with a private key.
fn to_json<T: serde::Serialize>(value: &T) -> Result<String, PassboltFfiError> {
    serde_json::to_string(value).map_err(|error| PassboltFfiError::Other {
        message: format!("Cannot write JSON: {error}"),
    })
}

fn from_json<T: serde::de::DeserializeOwned>(json: &str) -> Result<T, PassboltFfiError> {
    serde_json::from_str(json).map_err(|error| PassboltFfiError::InvalidArgument {
        message: format!("Invalid JSON: {error}"),
    })
}

#[uniffi::export]
pub fn decrypt_message(
    armored_message: String,
    private_key_armored: String,
    passphrase: String,
) -> Result<Vec<u8>, PassboltFfiError> {
    let key = passbolt_sdk::crypto::parse_private_key(&private_key_armored).map_err(|error| {
        PassboltFfiError::Crypto {
            message: error.to_string(),
        }
    })?;
    passbolt_sdk::crypto::decrypt_message(&armored_message, &key.key, &passphrase).map_err(
        |error| PassboltFfiError::Crypto {
            message: error.to_string(),
        },
    )
}

/// Encrypt a plaintext message for one or more PGP public keys.
/// Returns the PGP-armored ciphertext.
#[uniffi::export]
pub fn encrypt_message(
    plaintext: Vec<u8>,
    public_keys_armored: Vec<String>,
) -> Result<String, PassboltFfiError> {
    let parsed: Result<Vec<_>, _> = public_keys_armored
        .iter()
        .map(|armored_key| passbolt_sdk::crypto::parse_public_key(armored_key))
        .collect();
    let keys = parsed.map_err(|error| PassboltFfiError::Crypto {
        message: error.to_string(),
    })?;
    let key_refs: Vec<_> = keys.iter().collect();
    passbolt_sdk::crypto::encrypt_message(&plaintext, &key_refs).map_err(|error| {
        PassboltFfiError::Crypto {
            message: error.to_string(),
        }
    })
}

/// Parse a PGP private key and return its fingerprint (hex uppercase).
#[uniffi::export]
pub fn get_key_fingerprint(private_key_armored: String) -> Result<String, PassboltFfiError> {
    let key = passbolt_sdk::crypto::parse_private_key(&private_key_armored).map_err(|error| {
        PassboltFfiError::Crypto {
            message: error.to_string(),
        }
    })?;
    Ok(key.fingerprint.clone())
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use secrecy::ExposeSecret;

    use super::*;

    const ADA_PRIVATE: &str =
        include_str!("../../passbolt-sdk/tests/fixtures/keys/ada_private.asc");
    const ADA_PUBLIC: &str = include_str!("../../passbolt-sdk/tests/fixtures/keys/ada_public.asc");
    const BETTY_PUBLIC: &str =
        include_str!("../../passbolt-sdk/tests/fixtures/keys/betty_public.asc");
    const SERVER_PRIVATE: &str =
        include_str!("../../passbolt-sdk/tests/fixtures/keys/server_private.asc");
    const SERVER_PUBLIC: &str =
        include_str!("../../passbolt-sdk/tests/fixtures/keys/server_public.asc");

    fn config_with(proxy: Option<&str>, mfa_totp_token: Option<&str>) -> SdkConfig {
        build_sdk_config(
            "https://passbolt.test".into(),
            "armored key".into(),
            "secret passphrase".into(),
            FfiLoginOptions {
                tls_skip_verify: true,
                proxy: proxy.map(String::from),
                mfa_totp_token: mfa_totp_token.map(String::from),
                ..FfiLoginOptions::default()
            },
        )
    }

    #[rstest]
    #[case::absent(None)]
    #[case::empty(Some(""))]
    #[case::blank(Some("   "))]
    fn test_build_sdk_config_without_token_disables_mfa(#[case] mfa_totp_token: Option<&str>) {
        let config = config_with(None, mfa_totp_token);

        assert_eq!(config.mfa_mode, "");
        assert_eq!(config.mfa_totp_token, "");
        assert!(totp_provider(&config).unwrap().is_none());
    }

    #[test]
    fn test_build_sdk_config_with_token_enables_non_interactive_totp() {
        let config = config_with(None, Some("JBSWY3DPEHPK3PXP"));

        assert_eq!(config.mfa_mode, NON_INTERACTIVE_TOTP);
        assert_eq!(config.mfa_totp_token, "JBSWY3DPEHPK3PXP");
        assert!(totp_provider(&config).unwrap().is_some());
    }

    #[test]
    fn test_build_sdk_config_copies_credentials_and_tls_flag() {
        let config = config_with(None, None);

        assert_eq!(config.server_url, "https://passbolt.test");
        assert_eq!(config.private_key_armored, "armored key");
        assert_eq!(config.passphrase.expose_secret(), "secret passphrase");
        assert!(config.tls_skip_verify);
        assert_eq!(config.mfa_retrys, MFA_RETRY_COUNT);
    }

    #[test]
    fn test_build_sdk_config_carries_the_pinned_keys() {
        let config = build_sdk_config(
            "https://passbolt.test".into(),
            "armored key".into(),
            "secret passphrase".into(),
            FfiLoginOptions {
                server_public_key: Some(SERVER_PUBLIC.into()),
                metadata_key_fingerprint: Some("ABCD".into()),
                ..FfiLoginOptions::default()
            },
        );

        assert_eq!(config.server_public_key, SERVER_PUBLIC);
        assert_eq!(config.metadata_key_fingerprint, "ABCD");
    }

    #[rstest]
    #[case::absent(None, "")]
    #[case::empty(Some(""), "")]
    #[case::set(Some("http://proxy:3128"), "http://proxy:3128")]
    fn test_build_sdk_config_maps_proxy(#[case] proxy: Option<&str>, #[case] expected: &str) {
        let config = config_with(proxy, None);

        assert_eq!(config.proxy, expected);
    }

    #[rstest]
    #[case::absent(None, None)]
    #[case::empty(Some(""), None)]
    #[case::set(Some("http://proxy:3128"), Some("http://proxy:3128"))]
    fn test_build_http_config_maps_proxy_and_tls(
        #[case] proxy: Option<&str>,
        #[case] expected: Option<&str>,
        #[values(true, false)] tls_skip_verify: bool,
    ) {
        let http_config = build_http_config(&FfiLoginOptions {
            tls_skip_verify,
            proxy: proxy.map(String::from),
            ..FfiLoginOptions::default()
        });

        assert_eq!(http_config.proxy_url.as_deref(), expected);
        assert_eq!(http_config.tls_skip_verify, tls_skip_verify);
        assert!(http_config.client_cert_pem.is_none());
        assert!(http_config.client_key_pem.is_none());
        assert_eq!(http_config.resolve, Vec::new());
    }

    #[rstest]
    #[case::default(None, Some(std::time::Duration::from_secs(60)))]
    #[case::set(Some(5), Some(std::time::Duration::from_secs(5)))]
    #[case::forever(Some(0), None)]
    fn test_requests_time_out_after_a_minute_by_default(
        #[case] timeout_seconds: Option<u64>,
        #[case] expected: Option<std::time::Duration>,
    ) {
        let http_config = build_http_config(&FfiLoginOptions {
            timeout_seconds,
            ..FfiLoginOptions::default()
        });

        assert_eq!(http_config.timeout, expected);
    }

    #[test]
    fn test_the_client_certificate_goes_to_the_transport() {
        let http_config = build_http_config(&FfiLoginOptions {
            client_certificate_pem: Some("certificate".into()),
            client_key_pem: Some("key".into()),
            ..FfiLoginOptions::default()
        });

        assert_eq!(
            http_config.client_cert_pem.as_deref(),
            Some(&b"certificate"[..])
        );
        assert_eq!(http_config.client_key_pem.as_deref(), Some(&b"key"[..]));
    }

    #[test]
    fn test_encrypt_then_decrypt_message_round_trips() {
        let armored = encrypt_message(b"top secret".to_vec(), vec![SERVER_PUBLIC.into()]).unwrap();

        let plaintext = decrypt_message(armored, SERVER_PRIVATE.into(), String::new()).unwrap();

        assert_eq!(plaintext, b"top secret");
    }

    #[test]
    fn test_encrypt_message_for_several_keys_decrypts_with_each() {
        let armored = encrypt_message(
            b"shared".to_vec(),
            vec![SERVER_PUBLIC.into(), ADA_PUBLIC.into()],
        )
        .unwrap();

        let by_server = decrypt_message(armored.clone(), SERVER_PRIVATE.into(), String::new());
        let by_ada = decrypt_message(armored, ADA_PRIVATE.into(), "ada-passphrase".into());

        assert_eq!(by_server.unwrap(), b"shared");
        assert_eq!(by_ada.unwrap(), b"shared");
    }

    #[test]
    fn test_decrypt_message_with_wrong_key_is_crypto_error() {
        let armored = encrypt_message(b"for betty".to_vec(), vec![BETTY_PUBLIC.into()]).unwrap();

        let error = decrypt_message(armored, SERVER_PRIVATE.into(), String::new()).unwrap_err();

        assert!(matches!(error, PassboltFfiError::Crypto { .. }), "{error}");
    }

    #[test]
    fn test_decrypt_message_with_wrong_passphrase_is_crypto_error() {
        let armored = encrypt_message(b"for ada".to_vec(), vec![ADA_PUBLIC.into()]).unwrap();

        let error = decrypt_message(armored, ADA_PRIVATE.into(), "wrong".into()).unwrap_err();

        assert!(matches!(error, PassboltFfiError::Crypto { .. }), "{error}");
    }

    #[test]
    fn test_decrypt_message_with_invalid_private_key_is_crypto_error() {
        let error =
            decrypt_message("not a message".into(), "not a key".into(), String::new()).unwrap_err();

        assert!(matches!(error, PassboltFfiError::Crypto { .. }), "{error}");
    }

    #[test]
    fn test_encrypt_message_with_invalid_public_key_is_crypto_error() {
        let error = encrypt_message(b"data".to_vec(), vec!["not a key".into()]).unwrap_err();

        assert!(matches!(error, PassboltFfiError::Crypto { .. }), "{error}");
    }

    #[test]
    fn test_get_key_fingerprint_is_uppercase_hex() {
        let fingerprint = get_key_fingerprint(SERVER_PRIVATE.into()).unwrap();

        assert_eq!(fingerprint.len(), 40);
        assert!(fingerprint
            .chars()
            .all(|character| matches!(character, '0'..='9' | 'A'..='F')));
    }

    #[test]
    fn test_get_key_fingerprint_with_invalid_key_is_crypto_error() {
        let error = get_key_fingerprint("not a key".into()).unwrap_err();

        assert!(matches!(error, PassboltFfiError::Crypto { .. }), "{error}");
    }
}
