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
//! import passbolt
//!
//! with passbolt.Client.login("https://passbolt.example.com", private_key, passphrase) as client:
//!     resources = client.list_resources()
//! ```

mod error;
mod generator;
mod mfa;
mod resource;
mod types;

pub use error::PassboltError;
pub use generator::{
    default_password_policies, generate_passphrase, generate_password, generate_pin_code,
    generate_secret, secret_entropy, secret_strength, GeneratorType, PassphraseGeneratorSettings,
    PasswordGeneratorSettings, PasswordPolicies, Strength, WordCase,
};
pub use resource::{NewResource, ResourceChanges, ResourceView};
pub use types::{MetadataKeysSettings, MetadataTypesSettings, PasswordExpirySettings};

uniffi::setup_scaffolding!();

use std::future::Future;
use std::sync::{Arc, LazyLock};

use passbolt_sdk::config::SdkConfig;
use passbolt_sdk::platform::native::{NativeHttpClient, NativeHttpConfig};
use passbolt_sdk::{MfaProvider, PassboltSdk};

use crate::mfa::{totp_provider, NON_INTERACTIVE_TOTP};
use crate::types::{
    Aro, Comment, DeleteBlockers, Favorite, Folder, FolderQuery, FolderTreeNode, Group,
    GroupDeleteDryRun, Permission, Resource, ResourceQuery, ResourceType, SecretData, Tag, User,
    UserDeleteDryRun, UserQuery,
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

fn build_http_config(options: &LoginOptions) -> NativeHttpConfig {
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
pub struct LoginOptions {
    #[uniffi(default = false)]
    pub tls_skip_verify: bool,
    #[uniffi(default = None)]
    pub proxy: Option<String>,
    /// The base32 TOTP secret answering the MFA challenge without prompting.
    #[uniffi(default = None)]
    pub mfa_totp_token: Option<String>,
    /// The armored server public key pinned with [`fetch_server_key`]: each login then checks
    /// the server holds its private key.
    #[uniffi(default = None)]
    pub server_public_key: Option<String>,
    /// The shared metadata key fingerprint pinned with
    /// [`PassboltClient::metadata_key_fingerprint`]: shared metadata is then only encrypted
    /// for that key.
    #[uniffi(default = None)]
    pub metadata_key_fingerprint: Option<String>,
    /// Seconds a request may take; `None` is 60, `0` waits forever.
    #[uniffi(default = None)]
    pub timeout_seconds: Option<u64>,
    /// PEM certificate and private key, for a server asking for a client certificate (mTLS).
    #[uniffi(default = None)]
    pub client_certificate_pem: Option<String>,
    #[uniffi(default = None)]
    pub client_key_pem: Option<String>,
}

/// The server public key, to pin.
#[derive(uniffi::Record)]
pub struct ServerKey {
    /// Computed from the key, checked against the one the server announces.
    pub fingerprint: String,
    pub armored_key: String,
}

/// An empty or blank `mfa_totp_token` means no non-interactive MFA.
fn build_sdk_config(
    server_url: String,
    private_key_armored: String,
    passphrase: String,
    options: LoginOptions,
) -> SdkConfig {
    let LoginOptions {
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
        openpgp: passbolt_sdk::OpenPgp::default(),
    }
}

// ── PassboltClient ──────────────────────────────────────────────────────────

/// Log in with `GPGAuth` on the runtime: the session the two clients share.
async fn log_in(
    server_url: String,
    private_key_armored: String,
    passphrase: String,
    options: LoginOptions,
) -> Result<Arc<Client>, PassboltError> {
    let http_config = build_http_config(&options);
    let config = build_sdk_config(server_url, private_key_armored, passphrase, options);
    let mfa_provider = totp_provider(&config).map_err(|error| PassboltError::Config {
        reason: error.to_string(),
    })?;
    let http = NativeHttpClient::new(&http_config).map_err(|error| PassboltError::Config {
        reason: error.to_string(),
    })?;
    let client = Client::login(
        http,
        &config,
        mfa_provider.map(|provider| Box::new(provider) as Box<dyn MfaProvider>),
        config.mfa_retrys,
    )
    .await?;
    Ok(Arc::new(client))
}

/// Wait for `call` on the runtime, for the blocking client.
fn block_on<T>(call: impl Future<Output = Result<T, PassboltError>>) -> Result<T, PassboltError> {
    RUNTIME.block_on(call)
}

/// Run `call` on the runtime and await it from the caller's executor, for the async client:
/// the runtime serves the sockets, whatever polls the result.
async fn spawn<T: Send + 'static>(
    call: impl Future<Output = Result<T, PassboltError>> + Send + 'static,
) -> Result<T, PassboltError> {
    RUNTIME.spawn(call).await.unwrap_or_else(|error| {
        Err(PassboltError::Other {
            reason: error.to_string(),
        })
    })
}

/// Authenticated Passbolt client for CRUD operations.
///
/// All methods are synchronous at the FFI boundary; they block internally
/// on the tokio runtime. Call from background threads on mobile platforms, or use
/// [`AsyncPassboltClient`].
#[derive(uniffi::Object)]
pub struct PassboltClient {
    inner: Arc<Client>,
}

/// The same client with async methods: `await` them, they do not block the caller's thread.
#[derive(uniffi::Object)]
pub struct AsyncPassboltClient {
    inner: Arc<Client>,
}

/// The methods of both clients, from one list: each body is async, with `client` the
/// session; `PassboltClient` blocks on it, `AsyncPassboltClient` awaits it.
macro_rules! client_methods {
    ($(
        $(#[$attribute:meta])*
        fn $name:ident($client:ident $(, $argument:ident: $argument_type:ty)* $(,)?) -> $output:ty $body:block
    )*) => {
        #[uniffi::export]
        impl PassboltClient {
            $(
                $(#[$attribute])*
                pub fn $name(&self $(, $argument: $argument_type)*) -> $output {
                    let $client = Arc::clone(&self.inner);
                    block_on(async move $body)
                }
            )*
        }

        #[uniffi::export]
        impl AsyncPassboltClient {
            $(
                $(#[$attribute])*
                pub async fn $name(&self $(, $argument: $argument_type)*) -> $output {
                    let $client = Arc::clone(&self.inner);
                    spawn(async move $body).await
                }
            )*
        }
    };
}

#[uniffi::export]
impl PassboltClient {
    /// Authenticate against a Passbolt server and return a client session.
    #[uniffi::constructor]
    pub fn login(
        server_url: String,
        private_key_armored: String,
        passphrase: String,
    ) -> Result<Arc<Self>, PassboltError> {
        Self::login_with_config(
            server_url,
            private_key_armored,
            passphrase,
            LoginOptions::default(),
        )
    }

    /// Authenticate with `options`, the pinned server and metadata keys among them.
    #[uniffi::constructor]
    pub fn login_with_config(
        server_url: String,
        private_key_armored: String,
        passphrase: String,
        options: LoginOptions,
    ) -> Result<Arc<Self>, PassboltError> {
        let inner = block_on(log_in(server_url, private_key_armored, passphrase, options))?;
        Ok(Arc::new(Self { inner }))
    }

    /// Get the current user's ID.
    #[must_use]
    pub fn user_id(&self) -> String {
        self.inner.user_id.clone()
    }

    /// Get the server base URL.
    #[must_use]
    pub fn base_url(&self) -> String {
        self.inner.base_url.clone()
    }
}

#[uniffi::export]
impl AsyncPassboltClient {
    /// Authenticate against a Passbolt server and return a client session.
    #[uniffi::constructor]
    pub async fn login(
        server_url: String,
        private_key_armored: String,
        passphrase: String,
    ) -> Result<Arc<Self>, PassboltError> {
        Self::login_with_config(
            server_url,
            private_key_armored,
            passphrase,
            LoginOptions::default(),
        )
        .await
    }

    /// Authenticate with `options`, the pinned server and metadata keys among them.
    #[uniffi::constructor]
    pub async fn login_with_config(
        server_url: String,
        private_key_armored: String,
        passphrase: String,
        options: LoginOptions,
    ) -> Result<Arc<Self>, PassboltError> {
        let inner = spawn(log_in(server_url, private_key_armored, passphrase, options)).await?;
        Ok(Arc::new(Self { inner }))
    }

    /// Get the current user's ID.
    #[must_use]
    pub fn user_id(&self) -> String {
        self.inner.user_id.clone()
    }

    /// Get the server base URL.
    #[must_use]
    pub fn base_url(&self) -> String {
        self.inner.base_url.clone()
    }
}

client_methods! {
    // ── Auth ────────────────────────────────────────────────────────────

    /// Terminate the server-side session.
    fn logout(client) -> Result<(), PassboltError> {
        client.logout().await.map_err(PassboltError::from)
    }

    /// Check if the session is still valid.
    fn check_auth(client) -> Result<bool, PassboltError> {
        client.check_auth_status().await.map_err(Into::into)
    }

    // ── Resources ───────────────────────────────────────────────────────

    /// List resources with optional search and filters.
    #[uniffi::method(default(search = None, favorites_only = false, owned_by_me = false))]
    fn list_resources(
        client,
        search: Option<String>,
        favorites_only: bool,
        owned_by_me: bool,
    ) -> Result<Vec<Resource>, PassboltError> {
        let query = ResourceQuery {
            search,
            favorites_only,
            owned_by_me,
        };
        let resources = client
            .get_resources(query.into())
            .await
            .map_err(PassboltError::from)?;
        Ok(resources.into_iter().map(Resource::from).collect())
    }

    /// A resource with its v5 metadata and its secret decrypted, for every resource type.
    fn get_resource_view(client, id: String) -> Result<ResourceView, PassboltError> {
        let view = passbolt_sdk::resource::get::get_resource_view(&client, &id)
            .await
            .map_err(PassboltError::from)?;
        Ok(ResourceView::from(view))
    }

    /// Resources with their v5 metadata decrypted, searched by their decrypted name; their
    /// secrets too with `with_secrets`. One that does not decrypt has an `error`.
    #[uniffi::method(default(search = None, with_secrets = false))]
    fn list_resource_views(
        client,
        search: Option<String>,
        with_secrets: bool,
    ) -> Result<Vec<ResourceView>, PassboltError> {
        let query = passbolt_sdk::ResourceQuery {
            search,
            ..Default::default()
        };
        let views = passbolt_sdk::resource::list::list_resources(
            &client,
            query,
            &[],
            with_secrets.then_some(0),
        )
        .await
        .map_err(PassboltError::from)?;
        Ok(views.into_iter().map(ResourceView::from).collect())
    }

    /// Create a resource of any type. Returns the created resource.
    fn create_resource(
        client,
        resource: NewResource,
    ) -> Result<Resource, PassboltError> {
        let new_resource = resource.try_into()?;
        let resource = passbolt_sdk::resource::create::create_resource(&client, &new_resource)
            .await
            .map_err(PassboltError::from)?;
        Ok(Resource::from(resource))
    }

    /// Update a resource; the fields left out keep their value.
    fn update_resource(
        client,
        id: String,
        changes: ResourceChanges,
    ) -> Result<Resource, PassboltError> {
        let changes = changes.try_into()?;
        let resource = passbolt_sdk::resource::update::update_resource(&client, &id, &changes)
            .await
            .map_err(PassboltError::from)?;
        Ok(Resource::from(resource))
    }

    /// Share a resource with users and groups (`permission_type` 1, 7 or 15), or revoke with -1.
    #[uniffi::method(default(user_ids = [], group_ids = []))]
    fn share_resource(
        client,
        id: String,
        permission_type: i32,
        user_ids: Vec<String>,
        group_ids: Vec<String>,
    ) -> Result<(), PassboltError> {
        passbolt_sdk::resource::share::share_resource(
            &client,
            &id,
            &user_ids,
            &group_ids,
            permission_type,
        )
        .await
        .map_err(Into::into)
    }

    /// Share a folder, and with `with_content` the sub-folders and resources the user owns.
    #[uniffi::method(default(user_ids = [], group_ids = [], with_content = false))]
    fn share_folder(
        client,
        id: String,
        permission_type: i32,
        user_ids: Vec<String>,
        group_ids: Vec<String>,
        with_content: bool,
    ) -> Result<(), PassboltError> {
        passbolt_sdk::folder::share::share_folder(
            &client,
            &id,
            &user_ids,
            &group_ids,
            permission_type,
            with_content,
        )
        .await
        .map_err(Into::into)
    }

    /// Move a resource into a folder, or to the root without one.
    #[uniffi::method(default(folder_id = None))]
    fn move_resource(
        client,
        id: String,
        folder_id: Option<String>,
    ) -> Result<(), PassboltError> {
        client
            .move_resource(&id, folder_id.as_deref())
            .await
            .map_err(Into::into)
    }

    /// Move a folder into another one, or to the root without one.
    #[uniffi::method(default(folder_id = None))]
    fn move_folder(
        client,
        id: String,
        folder_id: Option<String>,
    ) -> Result<(), PassboltError> {
        client
            .move_folder(&id, folder_id.as_deref())
            .await
            .map_err(Into::into)
    }

    /// Get a single resource by ID.
    fn get_resource(client, id: String) -> Result<Resource, PassboltError> {
        let resource = client
            .get_resource(&id)
            .await
            .map_err(PassboltError::from)?;
        Ok(Resource::from(resource))
    }

    /// Get multiple resources by IDs.
    fn get_resources_by_ids(
        client,
        ids: Vec<String>,
    ) -> Result<Vec<Resource>, PassboltError> {
        let resources = client
            .get_resources_by_ids(&ids)
            .await
            .map_err(PassboltError::from)?;
        Ok(resources.into_iter().map(Resource::from).collect())
    }

    /// Decrypt a resource's secret. Pass the resource obtained from `get_resource`.
    fn decrypt_resource_secret(
        client,
        resource_id: String,
    ) -> Result<SecretData, PassboltError> {
        let resource = client
            .get_resource(&resource_id)
            .await
            .map_err(PassboltError::from)?;
        let secret = client
            .decrypt_resource_secret(&resource)
            .await
            .map_err(PassboltError::from)?;
        Ok(SecretData::from(secret))
    }

    /// Delete a resource.
    fn delete_resource(client, id: String) -> Result<(), PassboltError> {
        client.delete_resource(&id).await.map_err(Into::into)
    }

    /// Bulk delete resources.
    fn delete_resources(client, ids: Vec<String>) -> Result<(), PassboltError> {
        client.delete_resources(&ids).await.map_err(Into::into)
    }

    /// Get permissions for a resource.
    fn get_resource_permissions(
        client,
        id: String,
    ) -> Result<Vec<Permission>, PassboltError> {
        let permissions = client
            .get_resource_permissions(&id)
            .await
            .map_err(PassboltError::from)?;
        Ok(permissions.into_iter().map(Permission::from).collect())
    }

    // ── Folders ─────────────────────────────────────────────────────────

    /// List all folders.
    #[uniffi::method(default(search = None))]
    fn list_folders(
        client,
        search: Option<String>,
    ) -> Result<Vec<Folder>, PassboltError> {
        let query = FolderQuery { search };
        let folders = client
            .get_folders(query.into())
            .await
            .map_err(PassboltError::from)?;
        Ok(folders.into_iter().map(Folder::from).collect())
    }

    /// Get a single folder by ID.
    fn get_folder(client, id: String) -> Result<Folder, PassboltError> {
        let folder = client.get_folder(&id).await.map_err(PassboltError::from)?;
        Ok(Folder::from(folder))
    }

    /// Create a folder, at the root or in `folder_parent_id`; in a parent folder it gets the
    /// parent's permissions.
    #[uniffi::method(default(folder_parent_id = None))]
    fn create_folder(
        client,
        name: String,
        folder_parent_id: Option<String>,
    ) -> Result<Folder, PassboltError> {
        let folder = passbolt_sdk::folder::create::create_folder(
            &client,
            &name,
            folder_parent_id.as_deref(),
        )
        .await
        .map_err(PassboltError::from)?;
        Ok(Folder::from(folder))
    }

    /// Rename a folder.
    fn rename_folder(
        client,
        id: String,
        name: String,
    ) -> Result<Folder, PassboltError> {
        let payload = passbolt_sdk::types::UpdateFolderPayload { name };
        let folder = client
            .update_folder(&id, &payload)
            .await
            .map_err(PassboltError::from)?;
        Ok(Folder::from(folder))
    }

    /// Delete a folder; its content moves to the root.
    fn delete_folder(client, id: String) -> Result<(), PassboltError> {
        client.delete_folder(&id).await.map_err(Into::into)
    }

    /// Delete a folder with its sub-folders and the resources the user may delete in them.
    fn delete_folder_with_content(client, id: String) -> Result<(), PassboltError> {
        client
            .delete_folder_with_content(&id)
            .await
            .map_err(Into::into)
    }

    /// Get permissions for a folder.
    fn get_folder_permissions(
        client,
        id: String,
    ) -> Result<Vec<Permission>, PassboltError> {
        let permissions = client
            .get_folder_permissions(&id)
            .await
            .map_err(PassboltError::from)?;
        Ok(permissions.into_iter().map(Permission::from).collect())
    }

    /// Build a folder tree from the flat folder list.
    fn get_folder_tree(client) -> Result<Vec<FolderTreeNode>, PassboltError> {
        let folders = client
            .get_folders(passbolt_sdk::FolderQuery::default())
            .await
            .map_err(PassboltError::from)?;
        let tree = passbolt_sdk::build_folder_tree(&folders);
        Ok(tree.into_iter().map(FolderTreeNode::from).collect())
    }

    // ── Users ───────────────────────────────────────────────────────────

    /// List all users.
    #[uniffi::method(default(search = None, group_id = None, admin_only = false))]
    fn list_users(
        client,
        search: Option<String>,
        group_id: Option<String>,
        admin_only: bool,
    ) -> Result<Vec<User>, PassboltError> {
        let query = UserQuery {
            search,
            group_id,
            admin_only,
        };
        let users = client
            .get_users(query.into())
            .await
            .map_err(PassboltError::from)?;
        Ok(users.into_iter().map(User::from).collect())
    }

    /// Get the currently logged-in user.
    fn get_me(client) -> Result<User, PassboltError> {
        let user = client.get_me().await.map_err(PassboltError::from)?;
        Ok(User::from(user))
    }

    /// Get a user by ID.
    fn get_user(client, id: String) -> Result<User, PassboltError> {
        let user = client.get_user(&id).await.map_err(PassboltError::from)?;
        Ok(User::from(user))
    }

    /// Delete a user.
    fn delete_user(client, id: String) -> Result<(), PassboltError> {
        client.delete_user(&id).await.map_err(Into::into)
    }

    /// Preview the impact of deleting a user.
    fn delete_user_dry_run(
        client,
        id: String,
    ) -> Result<UserDeleteDryRun, PassboltError> {
        let result = client
            .delete_user_dry_run(&id)
            .await
            .map_err(PassboltError::from)?;
        Ok(UserDeleteDryRun::from(result))
    }

    /// Create a user with the role named `role` (`user` or `admin`).
    fn create_user(
        client,
        username: String,
        first_name: String,
        last_name: String,
        role: String,
    ) -> Result<User, PassboltError> {
        let user = passbolt_sdk::user::create::create_user(
            &client,
            &username,
            &first_name,
            &last_name,
            &role,
        )
        .await
        .map_err(PassboltError::from)?;
        Ok(User::from(user))
    }

    /// Update a user's names or role; `None` keeps the value.
    #[uniffi::method(default(first_name = None, last_name = None, role = None))]
    fn update_user(
        client,
        id: String,
        first_name: Option<String>,
        last_name: Option<String>,
        role: Option<String>,
    ) -> Result<User, PassboltError> {
        let user = passbolt_sdk::user::update::update_user(
            &client,
            &id,
            first_name.as_deref(),
            last_name.as_deref(),
            role.as_deref(),
        )
        .await
        .map_err(PassboltError::from)?;
        Ok(User::from(user))
    }

    /// What blocks deleting the user: what they alone own or manage.
    fn user_delete_blockers(
        client,
        id: String,
    ) -> Result<DeleteBlockers, PassboltError> {
        let blockers = client
            .user_delete_blockers(&id)
            .await
            .map_err(PassboltError::from)?;
        Ok(DeleteBlockers::from(blockers))
    }

    /// Delete a user, giving what they alone own or manage to `successor_id`, a user or a
    /// group that already has access to it.
    fn delete_user_with_transfer(
        client,
        id: String,
        successor_id: String,
    ) -> Result<(), PassboltError> {
        async {
            let blockers = client.user_delete_blockers(&id).await?;
            if blockers.is_empty() {
                return client.delete_user(&id).await;
            }
            let transfer = blockers.transfer_to(&successor_id)?;
            client.delete_user_with_transfer(&id, &transfer).await
        }
        .await
        .map_err(Into::into)
    }

    // ── Groups ──────────────────────────────────────────────────────────

    /// List all groups.
    fn list_groups(client) -> Result<Vec<Group>, PassboltError> {
        let groups = client
            .get_groups(passbolt_sdk::GroupQuery::default())
            .await
            .map_err(PassboltError::from)?;
        Ok(groups.into_iter().map(Group::from).collect())
    }

    /// Get a group by ID.
    fn get_group(client, id: String) -> Result<Group, PassboltError> {
        let group = client.get_group(&id).await.map_err(PassboltError::from)?;
        Ok(Group::from(group))
    }

    /// Delete a group.
    fn delete_group(client, id: String) -> Result<(), PassboltError> {
        client.delete_group(&id).await.map_err(Into::into)
    }

    /// Preview the impact of deleting a group.
    fn delete_group_dry_run(
        client,
        id: String,
    ) -> Result<GroupDeleteDryRun, PassboltError> {
        let result = client
            .delete_group_dry_run(&id)
            .await
            .map_err(PassboltError::from)?;
        Ok(GroupDeleteDryRun::from(result))
    }

    /// Create a group; a manager is also a member.
    #[uniffi::method(default(member_ids = [], manager_ids = []))]
    fn create_group(
        client,
        name: String,
        member_ids: Vec<String>,
        manager_ids: Vec<String>,
    ) -> Result<Group, PassboltError> {
        let group =
            passbolt_sdk::group::create::create_group(&client, &name, &member_ids, &manager_ids)
                .await
                .map_err(PassboltError::from)?;
        Ok(Group::from(group))
    }

    /// Rename a group and change its members: the removed ones first, then the added ones,
    /// who get the secrets of the group's resources. Giving a user the role they have, or
    /// removing a non-member, is an error.
    #[uniffi::method(default(name = None, add_member_ids = [], add_manager_ids = [], remove_member_ids = []))]
    fn update_group(
        client,
        id: String,
        name: Option<String>,
        add_member_ids: Vec<String>,
        add_manager_ids: Vec<String>,
        remove_member_ids: Vec<String>,
    ) -> Result<Group, PassboltError> {
        use passbolt_sdk::group::update::update_group;

        let adds = !add_member_ids.is_empty() || !add_manager_ids.is_empty();
        if remove_member_ids.is_empty() {
            let group = update_group(
                &client,
                &id,
                name.as_deref(),
                &add_member_ids,
                &add_manager_ids,
                false,
            )
            .await?;
            return Ok(Group::from(group));
        }
        let group =
            update_group(&client, &id, name.as_deref(), &remove_member_ids, &[], true).await?;
        if !adds {
            return Ok(Group::from(group));
        }
        let group =
            update_group(&client, &id, None, &add_member_ids, &add_manager_ids, false).await?;
        Ok(Group::from(group))
    }

    /// What blocks deleting the group: what it alone owns.
    fn group_delete_blockers(
        client,
        id: String,
    ) -> Result<DeleteBlockers, PassboltError> {
        let blockers = client
            .group_delete_blockers(&id)
            .await
            .map_err(PassboltError::from)?;
        Ok(DeleteBlockers::from(blockers))
    }

    /// Delete a group, giving what it alone owns to `successor_id`, a user or a group that
    /// already has access to it.
    fn delete_group_with_transfer(
        client,
        id: String,
        successor_id: String,
    ) -> Result<(), PassboltError> {
        async {
            let blockers = client.group_delete_blockers(&id).await?;
            if blockers.is_empty() {
                return client.delete_group(&id).await;
            }
            let transfer = blockers.transfer_to(&successor_id)?;
            client.delete_group_with_transfer(&id, &transfer).await
        }
        .await
        .map_err(Into::into)
    }

    // ── Tags ────────────────────────────────────────────────────────────

    /// List all tags.
    fn get_tags(client) -> Result<Vec<Tag>, PassboltError> {
        let tags = client.get_tags().await.map_err(PassboltError::from)?;
        Ok(tags.into_iter().map(Tag::from).collect())
    }

    /// Add a tag to a resource, keeping its other tags; returns the resource's tags.
    fn add_tag_to_resource(
        client,
        resource_id: String,
        slug: String,
    ) -> Result<Vec<Tag>, PassboltError> {
        let tags = client
            .add_tag_to_resource(&resource_id, &slug)
            .await
            .map_err(PassboltError::from)?;
        Ok(tags.into_iter().map(Tag::from).collect())
    }

    /// Replace all the tags of a resource; returns its tags.
    fn set_resource_tags(
        client,
        resource_id: String,
        slugs: Vec<String>,
    ) -> Result<Vec<Tag>, PassboltError> {
        let tags = client
            .update_resource_tags(&resource_id, &slugs)
            .await
            .map_err(PassboltError::from)?;
        Ok(tags.into_iter().map(Tag::from).collect())
    }

    /// Rename a tag.
    fn rename_tag(client, id: String, slug: String) -> Result<Tag, PassboltError> {
        let tag = client
            .update_tag(&id, &slug)
            .await
            .map_err(PassboltError::from)?;
        Ok(Tag::from(tag))
    }

    /// Delete a tag.
    fn delete_tag(client, id: String) -> Result<(), PassboltError> {
        client.delete_tag(&id).await.map_err(Into::into)
    }

    // ── Comments ────────────────────────────────────────────────────────

    /// Get comments for a resource.
    fn get_comments(
        client,
        resource_id: String,
    ) -> Result<Vec<Comment>, PassboltError> {
        let comments = client
            .get_comments(&resource_id)
            .await
            .map_err(PassboltError::from)?;
        Ok(comments.into_iter().map(Comment::from).collect())
    }

    /// Create a comment on a resource.
    #[uniffi::method(default(parent_id = None))]
    fn create_comment(
        client,
        resource_id: String,
        content: String,
        parent_id: Option<String>,
    ) -> Result<Comment, PassboltError> {
        let comment = client
            .create_comment(&resource_id, &content, parent_id.as_deref())
            .await
            .map_err(PassboltError::from)?;
        Ok(Comment::from(comment))
    }

    /// Delete a comment.
    fn delete_comment(client, id: String) -> Result<(), PassboltError> {
        client.delete_comment(&id).await.map_err(Into::into)
    }

    // ── Sharing ─────────────────────────────────────────────────────────

    /// Search for users and groups (AROs) for sharing.
    fn search_aros(client, search: String) -> Result<Vec<Aro>, PassboltError> {
        let aros = client
            .search_aros(&search)
            .await
            .map_err(PassboltError::from)?;
        Ok(aros.into_iter().map(Aro::from).collect())
    }

    // ── Favorites ───────────────────────────────────────────────────────

    /// Add a resource to favorites.
    fn add_favorite(client, resource_id: String) -> Result<Favorite, PassboltError> {
        let favorite = client
            .add_favorite(&resource_id)
            .await
            .map_err(PassboltError::from)?;
        Ok(Favorite::from(favorite))
    }

    /// Remove a favorite.
    fn remove_favorite(client, favorite_id: String) -> Result<(), PassboltError> {
        client
            .remove_favorite(&favorite_id)
            .await
            .map_err(Into::into)
    }

    // ── Password Expiry ─────────────────────────────────────────────────

    /// Get password expiry settings.
    fn get_password_expiry_settings(
        client,
    ) -> Result<PasswordExpirySettings, PassboltError> {
        let settings = client
            .get_password_expiry_settings()
            .await
            .map_err(PassboltError::from)?;
        Ok(PasswordExpirySettings::from(settings))
    }

    /// Create or update the password expiry settings (admin).
    fn save_password_expiry_settings(
        client,
        settings: PasswordExpirySettings,
    ) -> Result<PasswordExpirySettings, PassboltError> {
        let saved = client
            .save_password_expiry_settings(&settings.into())
            .await
            .map_err(PassboltError::from)?;
        Ok(PasswordExpirySettings::from(saved))
    }

    /// Delete the password expiry settings (admin): the defaults apply again.
    fn delete_password_expiry_settings(
        client,
        id: String,
    ) -> Result<(), PassboltError> {
        client
            .delete_password_expiry_settings(&id)
            .await
            .map_err(Into::into)
    }

    // ── Password policies ───────────────────────────────────────────────

    /// The password policies of the organization, for [`generate_secret`].
    fn get_password_policies(client) -> Result<PasswordPolicies, PassboltError> {
        let policies = client
            .get_password_policies()
            .await
            .map_err(PassboltError::from)?;
        Ok(PasswordPolicies::from(policies))
    }

    /// Save the password policies of the organization (administrator, Passbolt Pro).
    fn save_password_policies(
        client,
        policies: PasswordPolicies,
    ) -> Result<PasswordPolicies, PassboltError> {
        let saved = client
            .save_password_policies(&policies.into())
            .await
            .map_err(PassboltError::from)?;
        Ok(PasswordPolicies::from(saved))
    }

    // ── Resource types and metadata settings ────────────────────────────

    /// The resource types of the server.
    fn list_resource_types(client) -> Result<Vec<ResourceType>, PassboltError> {
        let resource_types = client.resource_types().await.map_err(PassboltError::from)?;
        Ok(resource_types.iter().map(ResourceType::from).collect())
    }

    /// Which metadata versions the organization creates and allows.
    fn get_metadata_types_settings(
        client,
    ) -> Result<MetadataTypesSettings, PassboltError> {
        let settings = client
            .get_metadata_types_settings()
            .await
            .map_err(PassboltError::from)?;
        Ok(MetadataTypesSettings::from(settings))
    }

    /// Save the metadata types settings (admin).
    fn save_metadata_types_settings(
        client,
        settings: MetadataTypesSettings,
    ) -> Result<MetadataTypesSettings, PassboltError> {
        let saved = client
            .save_metadata_types_settings(&settings.into())
            .await
            .map_err(PassboltError::from)?;
        Ok(MetadataTypesSettings::from(saved))
    }

    /// How metadata keys are used in the organization.
    fn get_metadata_keys_settings(
        client,
    ) -> Result<MetadataKeysSettings, PassboltError> {
        let settings = client
            .get_metadata_keys_settings()
            .await
            .map_err(PassboltError::from)?;
        Ok(MetadataKeysSettings::from(settings))
    }

    /// Save the metadata keys settings (admin).
    fn save_metadata_keys_settings(
        client,
        settings: MetadataKeysSettings,
    ) -> Result<MetadataKeysSettings, PassboltError> {
        let saved = client
            .save_metadata_keys_settings(&settings.into())
            .await
            .map_err(PassboltError::from)?;
        Ok(MetadataKeysSettings::from(saved))
    }

    // ── HIBP ────────────────────────────────────────────────────────────

    /// Check if a password has been exposed in data breaches.
    /// Returns the number of times found (0 = not breached).
    fn check_password_pwned(client, password: String) -> Result<u64, PassboltError> {
        client
            .check_password_pwned(&password)
            .await
            .map_err(Into::into)
    }

    // ── Session info ────────────────────────────────────────────────────

    /// Keep the session alive, as the browser extension does every few minutes.
    fn keep_alive(client) -> Result<(), PassboltError> {
        client.keep_alive().await.map_err(Into::into)
    }

    /// The fingerprint of the active shared metadata key, to pin in
    /// [`LoginOptions::metadata_key_fingerprint`]; `None` without one.
    fn metadata_key_fingerprint(client) -> Result<Option<String>, PassboltError> {
        let metadata_keys = client.metadata_keys().await.map_err(PassboltError::from)?;
        Ok(metadata_keys.active_fingerprint())
    }
}

/// The server public key, to pin in [`LoginOptions::server_public_key`] once the user
/// confirmed its fingerprint.
#[uniffi::export(default(tls_skip_verify = false))]
pub fn fetch_server_key(
    server_url: String,
    tls_skip_verify: bool,
) -> Result<ServerKey, PassboltError> {
    let http_config = build_http_config(&LoginOptions {
        tls_skip_verify,
        ..LoginOptions::default()
    });
    RUNTIME.block_on(async {
        let http = NativeHttpClient::new(&http_config).map_err(|error| PassboltError::Config {
            reason: error.to_string(),
        })?;
        let (fingerprint, armored_key) = passbolt_sdk::auth::fetch_server_key(
            &http,
            server_url.trim_end_matches('/'),
            &passbolt_sdk::OpenPgp::default(),
        )
        .await
        .map_err(PassboltError::from)?;
        Ok(ServerKey {
            fingerprint,
            armored_key,
        })
    })
}

// ── Stateless crypto functions ──────────────────────────────────────────────

/// Decrypt a PGP-armored message with a private key.
#[uniffi::export]
pub fn decrypt_message(
    armored_message: String,
    private_key_armored: String,
    passphrase: String,
) -> Result<Vec<u8>, PassboltError> {
    let key = passbolt_sdk::crypto::parse_private_key(&private_key_armored).map_err(|error| {
        PassboltError::Crypto {
            reason: error.to_string(),
        }
    })?;
    RUNTIME
        .block_on(passbolt_sdk::crypto::decrypt_message(
            &armored_message,
            &key,
            &passphrase,
        ))
        .map_err(|error| PassboltError::Crypto {
            reason: error.to_string(),
        })
}

/// Encrypt a plaintext message for one or more PGP public keys.
/// Returns the PGP-armored ciphertext.
#[uniffi::export]
pub fn encrypt_message(
    plaintext: Vec<u8>,
    public_keys_armored: Vec<String>,
) -> Result<String, PassboltError> {
    let parsed: Result<Vec<_>, _> = public_keys_armored
        .iter()
        .map(|armored_key| passbolt_sdk::crypto::parse_public_key(armored_key))
        .collect();
    let keys = parsed.map_err(|error| PassboltError::Crypto {
        reason: error.to_string(),
    })?;
    let key_refs: Vec<_> = keys.iter().collect();
    RUNTIME
        .block_on(passbolt_sdk::crypto::encrypt_message(&plaintext, &key_refs))
        .map_err(|error| PassboltError::Crypto {
            reason: error.to_string(),
        })
}

/// Parse a PGP private key and return its fingerprint (hex uppercase).
#[uniffi::export]
pub fn get_key_fingerprint(private_key_armored: String) -> Result<String, PassboltError> {
    let key = passbolt_sdk::crypto::parse_private_key(&private_key_armored).map_err(|error| {
        PassboltError::Crypto {
            reason: error.to_string(),
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
            LoginOptions {
                tls_skip_verify: true,
                proxy: proxy.map(String::from),
                mfa_totp_token: mfa_totp_token.map(String::from),
                ..LoginOptions::default()
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
            LoginOptions {
                server_public_key: Some(SERVER_PUBLIC.into()),
                metadata_key_fingerprint: Some("ABCD".into()),
                ..LoginOptions::default()
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
        let http_config = build_http_config(&LoginOptions {
            tls_skip_verify,
            proxy: proxy.map(String::from),
            ..LoginOptions::default()
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
        let http_config = build_http_config(&LoginOptions {
            timeout_seconds,
            ..LoginOptions::default()
        });

        assert_eq!(http_config.timeout, expected);
    }

    #[test]
    fn test_the_client_certificate_goes_to_the_transport() {
        let http_config = build_http_config(&LoginOptions {
            client_certificate_pem: Some("certificate".into()),
            client_key_pem: Some("key".into()),
            ..LoginOptions::default()
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

        assert!(matches!(error, PassboltError::Crypto { .. }), "{error}");
    }

    #[test]
    fn test_decrypt_message_with_wrong_passphrase_is_crypto_error() {
        let armored = encrypt_message(b"for ada".to_vec(), vec![ADA_PUBLIC.into()]).unwrap();

        let error = decrypt_message(armored, ADA_PRIVATE.into(), "wrong".into()).unwrap_err();

        assert!(matches!(error, PassboltError::Crypto { .. }), "{error}");
    }

    #[test]
    fn test_decrypt_message_with_invalid_private_key_is_crypto_error() {
        let error =
            decrypt_message("not a message".into(), "not a key".into(), String::new()).unwrap_err();

        assert!(matches!(error, PassboltError::Crypto { .. }), "{error}");
    }

    #[test]
    fn test_encrypt_message_with_invalid_public_key_is_crypto_error() {
        let error = encrypt_message(b"data".to_vec(), vec!["not a key".into()]).unwrap_err();

        assert!(matches!(error, PassboltError::Crypto { .. }), "{error}");
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

        assert!(matches!(error, PassboltError::Crypto { .. }), "{error}");
    }
}
