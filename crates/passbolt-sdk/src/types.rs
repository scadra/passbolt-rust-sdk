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

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ─── Pagination ──────────────────────────────────────────────────────────────

/// Pagination parameters for list queries.
#[derive(Debug, Clone, Default)]
pub struct PaginationParams {
    /// Request a specific page (1-indexed). If `None`, auto-paginate all pages.
    pub page: Option<u32>,
    /// Items per page. Server default if `None`.
    pub limit: Option<u32>,
}

/// Pagination metadata returned by the API.
#[derive(Debug, Clone, Deserialize)]
pub struct PaginationInfo {
    pub count: u32,
    pub page: u32,
    pub limit: Option<u32>,
}

// ─── Resource ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    pub id: String,
    /// Absent for v5 resources: the name is in the encrypted metadata.
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub uri: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub folder_parent_id: Option<String>,
    #[serde(default)]
    pub resource_type_id: Option<String>,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    #[serde(default)]
    pub created_by: Option<String>,
    #[serde(default)]
    pub modified_by: Option<String>,
    #[serde(default)]
    pub personal: Option<bool>,
    #[serde(default)]
    pub favorite: Option<Favorite>,
    #[serde(default)]
    pub secrets: Vec<Secret>,
    /// The user's own permission, with `contain[permission]=1`.
    #[serde(default)]
    pub permission: Option<Permission>,
    #[serde(default)]
    pub permissions: Vec<Permission>,
    /// With `contain[tag]=1`.
    #[serde(default)]
    pub tags: Vec<Tag>,
    /// v5: PGP-armored metadata string; v4: null/absent.
    #[serde(rename = "metadata", default)]
    pub metadata_armored: Option<serde_json::Value>,
    #[serde(default)]
    pub metadata_key_id: Option<String>,
    #[serde(default)]
    pub metadata_key_type: Option<String>,
    #[serde(default)]
    pub expired: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted: Option<bool>,
}

impl Resource {
    /// Returns `true` for v5 resources (metadata is PGP-encrypted).
    ///
    /// Not `metadata_key_id`: it is null for metadata encrypted with the user key.
    #[must_use]
    pub fn is_v5(&self) -> bool {
        self.armored_metadata().is_some()
    }

    /// Return the PGP-armored metadata string for v5 resources.
    #[must_use]
    pub fn armored_metadata(&self) -> Option<&str> {
        self.metadata_armored.as_ref()?.as_str()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Favorite {
    pub id: Option<String>,
    pub foreign_model: Option<String>,
    pub foreign_key: Option<String>,
    pub created: Option<DateTime<Utc>>,
}

// ─── v5 Metadata key API ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataKey {
    pub id: String,
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// Public key, used to encrypt shared metadata.
    #[serde(default)]
    pub armored_key: Option<String>,
    #[serde(default)]
    pub created: Option<DateTime<Utc>>,
    #[serde(default)]
    pub expired: Option<DateTime<Utc>>,
    #[serde(default)]
    pub deleted: Option<DateTime<Utc>>,
    #[serde(default)]
    pub metadata_private_keys: Vec<MetadataPrivateKeyShare>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataPrivateKeyShare {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub metadata_key_id: Option<String>,
    #[serde(default)]
    pub user_id: Option<String>,
    /// `PASSBOLT_METADATA_PRIVATE_KEY` JSON encrypted with the user's public key.
    pub data: String,
}

/// Decrypted v5 `metadata`, the `PASSBOLT_RESOURCE_METADATA` object.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceMetadata {
    // Absent fields stay absent: a type without `username` must not get `username: null`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_type_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uris: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// `{type, value, background_color}`, every field optional; kept as written.
    pub icon: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_fields: Option<Vec<CustomField>>,
    /// Fields this SDK does not know, kept so that an update writes them back.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl ResourceMetadata {
    /// The main URI: the first of `uris`.
    #[must_use]
    pub fn uri(&self) -> Option<&str> {
        self.uris.first().map(String::as_str)
    }
}

/// One side of a custom field: the metadata holds `metadata_*`, the secret `secret_*`.
///
/// Both sides share the `id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomField {
    pub id: String,
    /// `text`, `password`, `boolean`, `number` or `uri`.
    #[serde(rename = "type")]
    pub field_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_value: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_value: Option<serde_json::Value>,
}

// ─── Secret ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub id: Option<String>,
    pub resource_id: Option<String>,
    pub user_id: Option<String>,
    pub data: Option<String>,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
}

/// Plaintext secret data after decryption.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecretData {
    /// `PASSBOLT_SECRET_DATA` on v5 secrets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_type: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<TotpData>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_fields: Option<Vec<CustomField>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin_code: Option<String>,
    /// Fields this SDK does not know, kept so that an update writes them back.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
    /// Raw secret when `resource_type` is password-string
    #[serde(skip)]
    pub raw: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TotpData {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digits: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period: Option<u64>,
    /// Read from secrets written by older clients; Passbolt resource types have no issuer.
    #[serde(default, skip_serializing)]
    pub issuer: Option<String>,
}

// ─── ResourceType ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceType {
    pub id: String,
    pub slug: String,
    pub name: Option<String>,
    /// JSON Schemas of the `resource` (v4 fields or v5 metadata) and of the `secret`, as stored by the server.
    pub definition: Option<serde_json::Value>,
}

impl ResourceType {
    #[must_use]
    pub fn is_v5(&self) -> bool {
        self.slug.starts_with("v5-")
    }

    /// Schema of the v4 resource fields, or of the v5 metadata; `None` for an unknown slug.
    ///
    /// From the schemas bundled with the SDK, not `definition`: servers may keep outdated ones.
    #[must_use]
    pub fn resource_schema(&self) -> Option<&'static serde_json::Value> {
        crate::resource::schema::definition(&self.slug)?.get("resource")
    }

    #[must_use]
    pub fn secret_schema(&self) -> Option<&'static serde_json::Value> {
        crate::resource::schema::definition(&self.slug)?.get("secret")
    }

    /// `password-string` types: the secret is the password itself, not a JSON object.
    #[must_use]
    pub fn secret_is_string(&self) -> bool {
        self.secret_schema()
            .and_then(|schema| schema.get("type"))
            .is_some_and(|secret_type| secret_type == "string")
    }

    #[must_use]
    pub fn resource_has_field(&self, field: &str) -> bool {
        has_property(self.resource_schema(), field)
    }

    #[must_use]
    pub fn secret_has_field(&self, field: &str) -> bool {
        has_property(self.secret_schema(), field)
    }
}

fn has_property(schema: Option<&serde_json::Value>, field: &str) -> bool {
    schema
        .and_then(|schema| schema.get("properties")?.get(field))
        .is_some()
}

// ─── Folder ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Folder {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub folder_parent_id: Option<String>,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    #[serde(default)]
    pub created_by: Option<String>,
    #[serde(default)]
    pub modified_by: Option<String>,
    #[serde(default)]
    pub personal: Option<bool>,
    /// The user's own permission, with `contain[permission]=1`.
    #[serde(default)]
    pub permission: Option<Permission>,
    #[serde(default)]
    pub permissions: Vec<Permission>,
}

// ─── User ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: Option<String>,
    pub role_id: Option<String>,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    #[serde(default)]
    pub active: Option<bool>,
    #[serde(default)]
    pub deleted: Option<bool>,
    /// When the account was disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<String>,
    #[serde(default)]
    pub profile: Option<UserProfile>,
    #[serde(default)]
    pub role: Option<Role>,
    /// Sent as `gpgkey` by the API, serialized as `gpg_key`.
    #[serde(default, alias = "gpgkey")]
    pub gpg_key: Option<GpgKey>,
    #[serde(default)]
    pub groups_users: Vec<GroupUser>,
}

impl User {
    #[must_use]
    pub fn first_name(&self) -> &str {
        self.profile
            .as_ref()
            .and_then(|profile| profile.first_name.as_deref())
            .unwrap_or("")
    }

    #[must_use]
    pub fn last_name(&self) -> &str {
        self.profile
            .as_ref()
            .and_then(|profile| profile.last_name.as_deref())
            .unwrap_or("")
    }

    #[must_use]
    pub fn role_name(&self) -> &str {
        self.role
            .as_ref()
            .and_then(|role| role.name.as_deref())
            .unwrap_or("")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub avatar: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpgKey {
    pub id: Option<String>,
    pub user_id: Option<String>,
    pub armored_key: Option<String>,
    pub bits: Option<u32>,
    pub fingerprint: Option<String>,
    pub key_created: Option<DateTime<Utc>>,
}

// ─── Group ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    #[serde(default)]
    pub created_by: Option<String>,
    #[serde(default)]
    pub modified_by: Option<String>,
    #[serde(default)]
    pub deleted: Option<bool>,
    #[serde(default)]
    pub groups_users: Vec<GroupUser>,
    #[serde(default)]
    pub my_group_user: Option<GroupUser>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupUser {
    pub id: Option<String>,
    pub group_id: Option<String>,
    pub user_id: Option<String>,
    pub is_admin: Option<bool>,
    pub created: Option<DateTime<Utc>>,
    #[serde(default)]
    pub user: Option<Box<User>>,
}

// ─── Permission ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    pub id: Option<String>,
    pub aco: Option<String>,
    pub aco_foreign_key: Option<String>,
    pub aro: Option<String>,
    pub aro_foreign_key: Option<String>,
    #[serde(rename = "type")]
    pub permission_type: Option<i32>,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    #[serde(default)]
    pub user: Option<Box<User>>,
    #[serde(default)]
    pub group: Option<Box<Group>>,
}

impl Permission {
    #[must_use]
    pub const fn type_name(&self) -> &str {
        match self.permission_type {
            Some(1) => "Read",
            Some(7) => "Update",
            Some(15) => "Owner",
            _ => "Unknown",
        }
    }
}

// ─── Share ────────────────────────────────────────────────────────────────────

/// ACO (Access Control Object) type used in share requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareChange {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub aro: String,
    pub aro_foreign_key: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub permission_type: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delete: Option<bool>,
}

// ─── Create/Update payloads ──────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct CreateResourcePayload {
    /// v4 only: v5 resources carry their name in the encrypted `metadata`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder_parent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_type_id: Option<String>,
    pub secrets: Vec<SecretPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expired: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_key_type: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UpdateResourcePayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// `Some(Value::Null)` empties it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<serde_json::Value>,
    /// `Some(Value::Null)` empties it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_type_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Vec<SecretPayload>>,
    /// `Some(Value::Null)` clears the expiry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expired: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_key_type: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SecretPayload {
    pub user_id: String,
    pub data: String,
}

#[derive(Debug, Serialize)]
pub struct CreateFolderPayload {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder_parent_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UpdateFolderPayload {
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct CreateUserPayload {
    pub username: String,
    pub role_id: Option<String>,
    pub profile: CreateUserProfile,
}

#[derive(Debug, Serialize)]
pub struct CreateUserProfile {
    pub first_name: String,
    pub last_name: String,
}

#[derive(Debug, Serialize)]
pub struct UpdateUserPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<UpdateUserProfile>,
}

#[derive(Debug, Serialize)]
pub struct UpdateUserProfile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateGroupPayload {
    pub name: String,
    pub groups_users: Vec<GroupUserPayload>,
}

#[derive(Debug, Serialize)]
pub struct UpdateGroupPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups_users: Option<Vec<GroupMembershipChange>>,
    /// The secrets new members need, from the update dry-run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Vec<GroupSecretPayload>>,
}

/// A membership change: a new member by `user_id`, or an existing membership by its `id`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct GroupMembershipChange {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_admin: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delete: Option<bool>,
}

/// A secret encrypted for a new group member.
#[derive(Debug, Clone, Serialize)]
pub struct GroupSecretPayload {
    pub resource_id: String,
    pub user_id: String,
    pub data: String,
}

#[derive(Debug, Serialize)]
pub struct GroupUserPayload {
    pub user_id: String,
    pub is_admin: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delete: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct MovePayload {
    pub folder_parent_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SharePayload {
    pub permissions: Vec<ShareChange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Vec<SecretPayload>>,
}

/// Build a list of share permission changes for users and groups.
#[must_use]
pub fn build_share_changes(
    user_ids: &[String],
    group_ids: &[String],
    permission_type: i32,
) -> Vec<ShareChange> {
    user_ids
        .iter()
        .map(|user_id| ShareChange {
            id: None,
            aro: "User".into(),
            aro_foreign_key: user_id.clone(),
            permission_type: Some(permission_type),
            delete: None,
        })
        .chain(group_ids.iter().map(|group_id| ShareChange {
            id: None,
            aro: "Group".into(),
            aro_foreign_key: group_id.clone(),
            permission_type: Some(permission_type),
            delete: None,
        }))
        .collect()
}

/// Build revoke changes from existing permissions for the given user/group IDs.
///
/// The Passbolt API requires the existing permission `id` and `delete: true` to revoke.
#[must_use]
pub fn build_revoke_changes(
    existing_permissions: &[Permission],
    user_ids: &[String],
    group_ids: &[String],
) -> Vec<ShareChange> {
    existing_permissions
        .iter()
        .filter(|permission| {
            let foreign_key = permission.aro_foreign_key.as_deref().unwrap_or("");
            match permission.aro.as_deref() {
                Some("User") => user_ids.iter().any(|user_id| user_id == foreign_key),
                Some("Group") => group_ids.iter().any(|group_id| group_id == foreign_key),
                _ => false,
            }
        })
        .filter_map(|permission| {
            let id = permission.id.clone()?;
            Some(ShareChange {
                id: Some(id),
                aro: permission.aro.clone().unwrap_or_default(),
                aro_foreign_key: permission.aro_foreign_key.clone().unwrap_or_default(),
                permission_type: None,
                delete: Some(true),
            })
        })
        .collect()
}

// ─── Tag ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tag {
    pub id: String,
    pub slug: String,
    #[serde(default)]
    pub is_shared: Option<bool>,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
}

// ─── Comment ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Comment {
    pub id: String,
    #[serde(default)]
    pub parent_id: Option<String>,
    #[serde(default)]
    pub foreign_key: Option<String>,
    #[serde(default)]
    pub foreign_model: Option<String>,
    pub content: String,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    #[serde(default)]
    pub created_by: Option<String>,
    #[serde(default)]
    pub modified_by: Option<String>,
    #[serde(default)]
    pub creator: Option<Box<User>>,
}

// ─── ARO (Access Request Object) ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Aro {
    pub id: String,
    #[serde(rename = "type", default)]
    pub aro_type: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub profile: Option<UserProfile>,
    #[serde(default)]
    pub name: Option<String>,
}

// ─── Password Expiry Settings ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordExpirySettings {
    #[serde(default)]
    pub id: Option<String>,
    /// Days; `default_expiry_period` in the API.
    #[serde(default, rename = "default_expiry_period")]
    pub default_expiry_period_days: Option<u32>,
    #[serde(default)]
    pub policy_override: Option<bool>,
    #[serde(default)]
    pub automatic_expiry: Option<bool>,
    #[serde(default)]
    pub automatic_update: Option<bool>,
}

// ─── Delete Dry-Run ──────────────────────────────────────────────────────────

/// Impact preview for deleting a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDeleteDryRun {
    #[serde(default)]
    pub resources_sole_owner_count: u32,
    #[serde(default)]
    pub folders_sole_owner_count: u32,
    #[serde(default)]
    pub groups_sole_manager_count: u32,
}

/// Impact preview for deleting a group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupDeleteDryRun {
    #[serde(default)]
    pub resources_sole_group_count: u32,
    #[serde(default)]
    pub folders_sole_group_count: u32,
}

// ─── Metadata Settings ───────────────────────────────────────────────────────

/// Controls which metadata versions are allowed for creation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MetadataTypesSettings {
    #[serde(default)]
    pub default_resource_types: Option<String>,
    #[serde(default)]
    pub default_folder_type: Option<String>,
    #[serde(default)]
    pub default_tag_type: Option<String>,
    #[serde(default)]
    pub default_comment_type: Option<String>,
    #[serde(default)]
    pub allow_creation_of_v5_resources: Option<bool>,
    #[serde(default)]
    pub allow_creation_of_v5_folders: Option<bool>,
    #[serde(default)]
    pub allow_creation_of_v5_tags: Option<bool>,
    #[serde(default)]
    pub allow_creation_of_v5_comments: Option<bool>,
    #[serde(default)]
    pub allow_creation_of_v4_resources: Option<bool>,
    #[serde(default)]
    pub allow_creation_of_v4_folders: Option<bool>,
    #[serde(default)]
    pub allow_creation_of_v4_tags: Option<bool>,
    #[serde(default)]
    pub allow_creation_of_v4_comments: Option<bool>,
}

impl MetadataTypesSettings {
    /// Resources are created as v5 unless the server says v4, its default.
    #[must_use]
    pub fn creates_v5_resources_by_default(&self) -> bool {
        self.default_resource_types.as_deref() == Some("v5")
    }

    /// Whether the server accepts new resources of that version, defaulting like the server.
    #[must_use]
    pub fn allows_resource_creation(&self, v5: bool) -> bool {
        if v5 {
            self.allow_creation_of_v5_resources.unwrap_or(false)
        } else {
            self.allow_creation_of_v4_resources.unwrap_or(true)
        }
    }
}

/// Controls metadata key behaviour (personal vs shared keys).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MetadataKeysSettings {
    #[serde(default)]
    pub allow_usage_of_personal_keys: Option<bool>,
    #[serde(default)]
    pub zero_knowledge_key_share: Option<bool>,
}

impl MetadataKeysSettings {
    /// Personal metadata is allowed unless the server says otherwise, its default.
    #[must_use]
    pub fn allows_personal_keys(&self) -> bool {
        self.allow_usage_of_personal_keys.unwrap_or(true)
    }
}

/// Both metadata settings, as a client needs them to create resources.
#[derive(Debug, Clone, Default)]
pub struct MetadataSettings {
    pub types: MetadataTypesSettings,
    pub keys: MetadataKeysSettings,
}

// ─── Metadata Private Key Sharing ────────────────────────────────────────────

/// Payload for sharing a metadata private key with a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataPrivateKeyPayload {
    pub metadata_key_id: String,
    pub user_id: String,
    /// PGP-encrypted metadata private key (armored), encrypted for the target user.
    pub data: String,
}

// ─── Folder Tree ─────────────────────────────────────────────────────────────

/// A node in a folder hierarchy tree.
#[derive(Debug, Clone)]
pub struct FolderTreeNode {
    pub folder: Folder,
    pub children: Vec<Self>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_settings_default_like_the_server() {
        let settings = MetadataSettings::default();

        assert!(!settings.types.creates_v5_resources_by_default());
        assert!(!settings.types.allows_resource_creation(true));
        assert!(settings.types.allows_resource_creation(false));
        assert!(settings.keys.allows_personal_keys());
    }

    #[test]
    fn test_an_unknown_resource_type_has_no_schema() {
        let resource_type = ResourceType {
            id: "t1".into(),
            slug: "v6-unknown".into(),
            name: None,
            definition: None,
        };

        assert!(resource_type.resource_schema().is_none());
        assert!(!resource_type.secret_is_string());
        assert!(!resource_type.resource_has_field("name"));
    }

    // ─── User ────────────────────────────────────────────────────────────────

    #[test]
    fn test_user_gpgkey_alias() {
        let user: User = serde_json::from_value(serde_json::json!({
            "id": "u1",
            "gpgkey": { "armored_key": "-----BEGIN PGP PUBLIC KEY BLOCK-----" }
        }))
        .unwrap();

        assert_eq!(
            user.gpg_key
                .and_then(|gpg_key| gpg_key.armored_key)
                .as_deref(),
            Some("-----BEGIN PGP PUBLIC KEY BLOCK-----")
        );
    }

    // ─── build_share_changes ─────────────────────────────────────────────────

    #[test]
    fn test_users_only() {
        let users = vec!["u1".into(), "u2".into()];
        let changes = build_share_changes(&users, &[], 7);
        assert_eq!(changes.len(), 2);
        assert!(changes.iter().all(|change| change.aro == "User"));
        assert!(changes
            .iter()
            .all(|change| change.permission_type == Some(7)));
        assert!(changes.iter().all(|change| change.delete.is_none()));
    }

    #[test]
    fn test_groups_only() {
        let groups = vec!["g1".into()];
        let changes = build_share_changes(&[], &groups, 1);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].aro, "Group");
        assert_eq!(changes[0].aro_foreign_key, "g1");
        assert_eq!(changes[0].permission_type, Some(1));
    }

    #[test]
    fn test_mixed_users_and_groups() {
        let users = vec!["u1".into()];
        let groups = vec!["g1".into()];
        let changes = build_share_changes(&users, &groups, 15);
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].aro, "User");
        assert_eq!(changes[1].aro, "Group");
    }

    #[test]
    fn test_permission_type_propagated() {
        let users = vec!["u1".into(), "u2".into()];
        let groups = vec!["g1".into()];
        let changes = build_share_changes(&users, &groups, 7);
        assert!(changes
            .iter()
            .all(|change| change.permission_type == Some(7)));
    }

    // ─── build_revoke_changes ─────────────────────────────────────────────────

    fn make_perm(id: &str, aro: &str, aro_foreign_key: &str) -> Permission {
        Permission {
            id: Some(id.into()),
            aco: None,
            aco_foreign_key: None,
            aro: Some(aro.into()),
            aro_foreign_key: Some(aro_foreign_key.into()),
            permission_type: Some(7),
            created: None,
            modified: None,
            user: None,
            group: None,
        }
    }

    #[test]
    fn test_revoke_user() {
        let permissions = vec![make_perm("perm-1", "User", "u1")];
        let changes = build_revoke_changes(&permissions, &["u1".into()], &[]);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].id, Some("perm-1".into()));
        assert_eq!(changes[0].delete, Some(true));
        assert!(changes[0].permission_type.is_none());
    }

    #[test]
    fn test_revoke_unknown_ignored() {
        let permissions = vec![make_perm("perm-1", "User", "u1")];
        let changes = build_revoke_changes(&permissions, &["u99".into()], &[]);
        assert!(changes.is_empty());
    }

    #[test]
    fn test_revoke_group() {
        let permissions = vec![make_perm("perm-2", "Group", "g1")];
        let changes = build_revoke_changes(&permissions, &[], &["g1".into()]);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].aro, "Group");
        assert_eq!(changes[0].delete, Some(true));
    }

    #[test]
    fn test_revoke_a_user_leaves_a_group_of_the_same_id() {
        let permissions = vec![make_perm("perm-2", "Group", "same-id")];
        let changes = build_revoke_changes(&permissions, &["same-id".into()], &[]);
        assert!(changes.is_empty());
    }

    #[test]
    fn test_revoke_perm_without_id_skipped() {
        let permission = Permission {
            id: None,
            aco: None,
            aco_foreign_key: None,
            aro: Some("User".into()),
            aro_foreign_key: Some("u1".into()),
            permission_type: Some(7),
            created: None,
            modified: None,
            user: None,
            group: None,
        };
        let changes = build_revoke_changes(&[permission], &["u1".into()], &[]);
        assert!(changes.is_empty());
    }
}
