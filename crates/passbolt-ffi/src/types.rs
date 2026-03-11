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
use passbolt_sdk::types;

// ── Helpers ─────────────────────────────────────────────────────────────────

fn to_iso(dt: Option<DateTime<Utc>>) -> Option<String> {
    dt.map(|date_time| date_time.to_rfc3339())
}

// ── Core domain types ───────────────────────────────────────────────────────

#[derive(uniffi::Record)]
pub struct FfiResource {
    pub id: String,
    pub name: String,
    pub username: Option<String>,
    pub uri: Option<String>,
    pub description: Option<String>,
    pub folder_parent_id: Option<String>,
    pub resource_type_id: Option<String>,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub created_by: Option<String>,
    pub modified_by: Option<String>,
    pub personal: Option<bool>,
    pub favorite: Option<FfiFavorite>,
    pub secrets: Vec<FfiSecret>,
    pub permissions: Vec<FfiPermission>,
    pub expired: Option<String>,
    /// v5 only: PGP-armored encrypted metadata.
    #[uniffi(default = None)]
    pub metadata: Option<String>,
    #[uniffi(default = None)]
    pub metadata_key_id: Option<String>,
    #[uniffi(default = None)]
    pub metadata_key_type: Option<String>,
}

impl From<types::Resource> for FfiResource {
    fn from(r: types::Resource) -> Self {
        Self {
            metadata: r.armored_metadata().map(String::from),
            metadata_key_id: r.metadata_key_id,
            metadata_key_type: r.metadata_key_type,
            id: r.id,
            name: r.name,
            username: r.username,
            uri: r.uri,
            description: r.description,
            folder_parent_id: r.folder_parent_id,
            resource_type_id: r.resource_type_id,
            created: to_iso(r.created),
            modified: to_iso(r.modified),
            created_by: r.created_by,
            modified_by: r.modified_by,
            personal: r.personal,
            favorite: r.favorite.map(FfiFavorite::from),
            secrets: r.secrets.into_iter().map(FfiSecret::from).collect(),
            permissions: r.permissions.into_iter().map(FfiPermission::from).collect(),
            expired: to_iso(r.expired),
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiFolder {
    pub id: String,
    pub name: String,
    pub folder_parent_id: Option<String>,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub created_by: Option<String>,
    pub modified_by: Option<String>,
    pub personal: Option<bool>,
    pub permissions: Vec<FfiPermission>,
}

impl From<types::Folder> for FfiFolder {
    fn from(f: types::Folder) -> Self {
        Self {
            id: f.id,
            name: f.name,
            folder_parent_id: f.folder_parent_id,
            created: to_iso(f.created),
            modified: to_iso(f.modified),
            created_by: f.created_by,
            modified_by: f.modified_by,
            personal: f.personal,
            permissions: f.permissions.into_iter().map(FfiPermission::from).collect(),
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiUser {
    pub id: String,
    pub username: Option<String>,
    pub role_id: Option<String>,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub active: Option<bool>,
    pub deleted: Option<bool>,
    pub profile: Option<FfiUserProfile>,
    pub role: Option<FfiRole>,
    pub gpg_key: Option<FfiGpgKey>,
    // groups_users excluded to break User ↔ GroupUser cycle
}

impl From<types::User> for FfiUser {
    fn from(u: types::User) -> Self {
        Self {
            id: u.id,
            username: u.username,
            role_id: u.role_id,
            created: to_iso(u.created),
            modified: to_iso(u.modified),
            active: u.active,
            deleted: u.deleted,
            profile: u.profile.map(FfiUserProfile::from),
            role: u.role.map(FfiRole::from),
            gpg_key: u.gpg_key.map(FfiGpgKey::from),
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiGroup {
    pub id: String,
    pub name: String,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub created_by: Option<String>,
    pub modified_by: Option<String>,
    pub deleted: Option<bool>,
    pub groups_users: Vec<FfiGroupUser>,
}

impl From<types::Group> for FfiGroup {
    fn from(g: types::Group) -> Self {
        Self {
            id: g.id,
            name: g.name,
            created: to_iso(g.created),
            modified: to_iso(g.modified),
            created_by: g.created_by,
            modified_by: g.modified_by,
            deleted: g.deleted,
            groups_users: g.groups_users.into_iter().map(FfiGroupUser::from).collect(),
        }
    }
}

// ── Nested types ────────────────────────────────────────────────────────────

#[derive(uniffi::Record)]
pub struct FfiPermission {
    pub id: Option<String>,
    pub aco: Option<String>,
    pub aco_foreign_key: Option<String>,
    pub aro: Option<String>,
    pub aro_foreign_key: Option<String>,
    pub permission_type: Option<i32>,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub user: Option<FfiUser>,
    pub group: Option<FfiGroup>,
}

impl From<types::Permission> for FfiPermission {
    fn from(p: types::Permission) -> Self {
        Self {
            id: p.id,
            aco: p.aco,
            aco_foreign_key: p.aco_foreign_key,
            aro: p.aro,
            aro_foreign_key: p.aro_foreign_key,
            permission_type: p.permission_type,
            created: to_iso(p.created),
            modified: to_iso(p.modified),
            user: p.user.map(|user| FfiUser::from(*user)),
            group: p.group.map(|group| FfiGroup::from(*group)),
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiSecret {
    pub id: Option<String>,
    pub resource_id: Option<String>,
    pub user_id: Option<String>,
    pub data: Option<String>,
    pub created: Option<String>,
    pub modified: Option<String>,
}

impl From<types::Secret> for FfiSecret {
    fn from(s: types::Secret) -> Self {
        Self {
            id: s.id,
            resource_id: s.resource_id,
            user_id: s.user_id,
            data: s.data,
            created: to_iso(s.created),
            modified: to_iso(s.modified),
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiSecretData {
    pub password: Option<String>,
    pub description: Option<String>,
    pub totp: Option<FfiTotpData>,
    pub raw: Option<String>,
}

impl From<types::SecretData> for FfiSecretData {
    fn from(s: types::SecretData) -> Self {
        Self {
            password: s.password,
            description: s.description,
            totp: s.totp.map(FfiTotpData::from),
            raw: s.raw,
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiTotpData {
    pub secret_key: Option<String>,
    pub algorithm: Option<String>,
    pub digits: Option<u32>,
    pub period: Option<u64>,
    pub issuer: Option<String>,
}

impl From<types::TotpData> for FfiTotpData {
    fn from(t: types::TotpData) -> Self {
        Self {
            secret_key: t.secret_key,
            algorithm: t.algorithm,
            digits: t.digits,
            period: t.period,
            issuer: t.issuer,
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiUserProfile {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

impl From<types::UserProfile> for FfiUserProfile {
    fn from(p: types::UserProfile) -> Self {
        Self {
            first_name: p.first_name,
            last_name: p.last_name,
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiGpgKey {
    pub id: Option<String>,
    pub user_id: Option<String>,
    pub armored_key: Option<String>,
    pub bits: Option<u32>,
    pub fingerprint: Option<String>,
    pub key_created: Option<String>,
}

impl From<types::GpgKey> for FfiGpgKey {
    fn from(k: types::GpgKey) -> Self {
        Self {
            id: k.id,
            user_id: k.user_id,
            armored_key: k.armored_key,
            bits: k.bits,
            fingerprint: k.fingerprint,
            key_created: to_iso(k.key_created),
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiGroupUser {
    pub id: Option<String>,
    pub group_id: Option<String>,
    pub user_id: Option<String>,
    pub is_admin: Option<bool>,
    pub created: Option<String>,
    // `user` excluded to break cycle: User ↔ GroupUser
}

impl From<types::GroupUser> for FfiGroupUser {
    fn from(gu: types::GroupUser) -> Self {
        Self {
            id: gu.id,
            group_id: gu.group_id,
            user_id: gu.user_id,
            is_admin: gu.is_admin,
            created: to_iso(gu.created),
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiRole {
    pub id: Option<String>,
    pub name: Option<String>,
}

impl From<types::Role> for FfiRole {
    fn from(r: types::Role) -> Self {
        Self {
            id: r.id,
            name: r.name,
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiFavorite {
    pub id: Option<String>,
    pub foreign_model: Option<String>,
    pub foreign_key: Option<String>,
    pub created: Option<String>,
}

impl From<types::Favorite> for FfiFavorite {
    fn from(f: types::Favorite) -> Self {
        Self {
            id: f.id,
            foreign_model: f.foreign_model,
            foreign_key: f.foreign_key,
            created: to_iso(f.created),
        }
    }
}

// ── Feature types ───────────────────────────────────────────────────────────

#[derive(uniffi::Record)]
pub struct FfiTag {
    pub id: String,
    pub slug: String,
    pub is_shared: Option<bool>,
    pub created: Option<String>,
    pub modified: Option<String>,
}

impl From<types::Tag> for FfiTag {
    fn from(t: types::Tag) -> Self {
        Self {
            id: t.id,
            slug: t.slug,
            is_shared: t.is_shared,
            created: to_iso(t.created),
            modified: to_iso(t.modified),
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiComment {
    pub id: String,
    pub parent_id: Option<String>,
    pub foreign_key: Option<String>,
    pub foreign_model: Option<String>,
    pub content: String,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub created_by: Option<String>,
    pub modified_by: Option<String>,
    pub creator: Option<FfiUser>,
}

impl From<types::Comment> for FfiComment {
    fn from(c: types::Comment) -> Self {
        Self {
            id: c.id,
            parent_id: c.parent_id,
            foreign_key: c.foreign_key,
            foreign_model: c.foreign_model,
            content: c.content,
            created: to_iso(c.created),
            modified: to_iso(c.modified),
            created_by: c.created_by,
            modified_by: c.modified_by,
            creator: c.creator.map(|user| FfiUser::from(*user)),
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiAro {
    pub id: String,
    pub aro_type: Option<String>,
    pub username: Option<String>,
    pub profile: Option<FfiUserProfile>,
    pub name: Option<String>,
}

impl From<types::Aro> for FfiAro {
    fn from(a: types::Aro) -> Self {
        Self {
            id: a.id,
            aro_type: a.aro_type,
            username: a.username,
            profile: a.profile.map(FfiUserProfile::from),
            name: a.name,
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiPasswordExpirySettings {
    pub id: Option<String>,
    pub default_expiry_period_days: Option<u32>,
    pub policy_override: Option<bool>,
    pub automatic_expiry: Option<bool>,
    pub automatic_update: Option<bool>,
}

impl From<types::PasswordExpirySettings> for FfiPasswordExpirySettings {
    fn from(s: types::PasswordExpirySettings) -> Self {
        Self {
            id: s.id,
            default_expiry_period_days: s.default_expiry_period_days,
            policy_override: s.policy_override,
            automatic_expiry: s.automatic_expiry,
            automatic_update: s.automatic_update,
        }
    }
}

#[derive(uniffi::Record)]
#[allow(clippy::struct_field_names)]
pub struct FfiUserDeleteDryRun {
    pub resources_sole_owner_count: u32,
    pub folders_sole_owner_count: u32,
    pub groups_sole_manager_count: u32,
}

impl From<types::UserDeleteDryRun> for FfiUserDeleteDryRun {
    fn from(d: types::UserDeleteDryRun) -> Self {
        Self {
            resources_sole_owner_count: d.resources_sole_owner_count,
            folders_sole_owner_count: d.folders_sole_owner_count,
            groups_sole_manager_count: d.groups_sole_manager_count,
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiGroupDeleteDryRun {
    pub resources_sole_group_count: u32,
    pub folders_sole_group_count: u32,
}

impl From<types::GroupDeleteDryRun> for FfiGroupDeleteDryRun {
    fn from(d: types::GroupDeleteDryRun) -> Self {
        Self {
            resources_sole_group_count: d.resources_sole_group_count,
            folders_sole_group_count: d.folders_sole_group_count,
        }
    }
}

/// A shared resource or folder only the deleted user or group owns, with its permissions.
#[derive(uniffi::Record)]
pub struct FfiOwnedItem {
    pub id: String,
    pub permissions: Vec<FfiPermission>,
}

impl From<passbolt_sdk::transfer::OwnedItem> for FfiOwnedItem {
    fn from(item: passbolt_sdk::transfer::OwnedItem) -> Self {
        Self {
            id: item.id,
            permissions: item
                .permissions
                .into_iter()
                .map(FfiPermission::from)
                .collect(),
        }
    }
}

/// A group with other members that only the deleted user manages, with its memberships.
#[derive(uniffi::Record)]
pub struct FfiManagedGroup {
    pub id: String,
    pub name: String,
    pub groups_users: Vec<FfiGroupUser>,
}

impl From<passbolt_sdk::transfer::ManagedGroup> for FfiManagedGroup {
    fn from(group: passbolt_sdk::transfer::ManagedGroup) -> Self {
        Self {
            id: group.id,
            name: group.name,
            groups_users: group
                .groups_users
                .into_iter()
                .map(FfiGroupUser::from)
                .collect(),
        }
    }
}

/// What blocks deleting a user or a group: each item needs a new owner, each group a new
/// manager.
#[derive(uniffi::Record)]
pub struct FfiDeleteBlockers {
    pub resources: Vec<FfiOwnedItem>,
    pub folders: Vec<FfiOwnedItem>,
    pub groups: Vec<FfiManagedGroup>,
    /// Groups the deleted user is the only member of: deleted with them.
    pub groups_to_delete: Vec<String>,
}

impl From<passbolt_sdk::transfer::DeleteBlockers> for FfiDeleteBlockers {
    fn from(blockers: passbolt_sdk::transfer::DeleteBlockers) -> Self {
        Self {
            resources: blockers
                .resources
                .into_iter()
                .map(FfiOwnedItem::from)
                .collect(),
            folders: blockers
                .folders
                .into_iter()
                .map(FfiOwnedItem::from)
                .collect(),
            groups: blockers
                .groups
                .into_iter()
                .map(FfiManagedGroup::from)
                .collect(),
            groups_to_delete: blockers.groups_to_delete,
        }
    }
}

// ── Query types (FFI → SDK) ────────────────────────────────────────────────

#[derive(uniffi::Record)]
pub struct FfiResourceQuery {
    pub search: Option<String>,
    pub favorites_only: bool,
    pub owned_by_me: bool,
}

impl From<FfiResourceQuery> for passbolt_sdk::ResourceQuery {
    fn from(q: FfiResourceQuery) -> Self {
        Self {
            search: q.search,
            favorites_only: q.favorites_only,
            owned_by_me: q.owned_by_me,
            ..Default::default()
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiFolderQuery {
    pub search: Option<String>,
}

impl From<FfiFolderQuery> for passbolt_sdk::FolderQuery {
    fn from(q: FfiFolderQuery) -> Self {
        Self {
            search: q.search,
            ..Default::default()
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiUserQuery {
    pub search: Option<String>,
    pub group_id: Option<String>,
    pub admin_only: bool,
}

impl From<FfiUserQuery> for passbolt_sdk::UserQuery {
    fn from(q: FfiUserQuery) -> Self {
        Self {
            search: q.search,
            group_id: q.group_id,
            admin_only: q.admin_only,
            ..Default::default()
        }
    }
}

// ── Folder tree ─────────────────────────────────────────────────────────────

#[derive(uniffi::Record)]
#[allow(clippy::use_self)] // uniffi::Record needs the concrete type name
pub struct FfiFolderTreeNode {
    pub folder: FfiFolder,
    pub children: Vec<FfiFolderTreeNode>,
}

impl From<types::FolderTreeNode> for FfiFolderTreeNode {
    fn from(node: types::FolderTreeNode) -> Self {
        Self {
            folder: FfiFolder::from(node.folder),
            children: node.children.into_iter().map(Self::from).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use rstest::rstest;
    use serde::de::DeserializeOwned;
    use serde_json::{json, Value};

    use super::*;

    const CREATED: &str = "2024-01-02T03:04:05+00:00";
    const MODIFIED: &str = "2024-06-07T08:09:10+00:00";

    fn parse<T: DeserializeOwned>(value: Value) -> T {
        serde_json::from_value(value).unwrap()
    }

    fn user_json(id: &str) -> Value {
        json!({
            "id": id,
            "username": "ada@passbolt.test",
            "role_id": "role-1",
            "created": CREATED,
            "modified": MODIFIED,
            "active": true,
            "deleted": false,
            "profile": { "first_name": "Ada", "last_name": "Lovelace", "avatar": { "url": "a.png" } },
            "role": { "id": "role-1", "name": "user" },
            "gpgkey": {
                "id": "key-1",
                "user_id": id,
                "armored_key": "-----BEGIN PGP PUBLIC KEY BLOCK-----",
                "bits": 2048,
                "fingerprint": "ABCDEF",
                "key_created": CREATED
            },
            "groups_users": [{ "id": "gu-1", "group_id": "group-1", "user_id": id }]
        })
    }

    fn group_json() -> Value {
        json!({
            "id": "group-1",
            "name": "Developers",
            "created": CREATED,
            "modified": MODIFIED,
            "created_by": "user-1",
            "modified_by": "user-2",
            "deleted": false,
            "groups_users": [{
                "id": "gu-1",
                "group_id": "group-1",
                "user_id": "user-1",
                "is_admin": true,
                "created": CREATED,
                "user": user_json("user-1")
            }]
        })
    }

    fn permission_json() -> Value {
        json!({
            "id": "permission-1",
            "aco": "Resource",
            "aco_foreign_key": "resource-1",
            "aro": "User",
            "aro_foreign_key": "user-1",
            "type": 15,
            "created": CREATED,
            "modified": MODIFIED,
            "user": user_json("user-1"),
            "group": group_json()
        })
    }

    fn folder_json(id: &str, parent_id: Option<&str>) -> Value {
        json!({
            "id": id,
            "name": format!("folder {id}"),
            "folder_parent_id": parent_id,
            "created": CREATED,
            "modified": MODIFIED,
            "created_by": "user-1",
            "modified_by": "user-2",
            "personal": false,
            "permissions": [permission_json()]
        })
    }

    #[rstest]
    #[case::utc(Utc.with_ymd_and_hms(2024, 1, 2, 3, 4, 5).unwrap(), CREATED)]
    #[case::subsecond(
        Utc.timestamp_opt(1_704_164_645, 123_000_000).unwrap(),
        "2024-01-02T03:04:05.123+00:00"
    )]
    fn test_to_iso_formats_rfc3339(#[case] date_time: DateTime<Utc>, #[case] expected: &str) {
        assert_eq!(to_iso(Some(date_time)).as_deref(), Some(expected));
    }

    #[test]
    fn test_to_iso_of_none_is_none() {
        assert_eq!(to_iso(None), None);
    }

    #[test]
    fn test_resource_v4_keeps_every_field() {
        let resource: types::Resource = parse(json!({
            "id": "resource-1",
            "name": "Gmail",
            "username": "ada",
            "uri": "https://mail.test",
            "description": "mail",
            "folder_parent_id": "folder-1",
            "resource_type_id": "type-1",
            "created": CREATED,
            "modified": MODIFIED,
            "created_by": "user-1",
            "modified_by": "user-2",
            "personal": true,
            "favorite": { "id": "favorite-1", "foreign_model": "Resource", "foreign_key": "resource-1", "created": CREATED },
            "secrets": [{ "id": "secret-1", "resource_id": "resource-1", "user_id": "user-1", "data": "PGP", "created": CREATED, "modified": MODIFIED }],
            "permissions": [permission_json()],
            "expired": MODIFIED
        }));

        let ffi_resource = FfiResource::from(resource);

        assert_eq!(ffi_resource.id, "resource-1");
        assert_eq!(ffi_resource.name, "Gmail");
        assert_eq!(ffi_resource.username.as_deref(), Some("ada"));
        assert_eq!(ffi_resource.uri.as_deref(), Some("https://mail.test"));
        assert_eq!(ffi_resource.description.as_deref(), Some("mail"));
        assert_eq!(ffi_resource.folder_parent_id.as_deref(), Some("folder-1"));
        assert_eq!(ffi_resource.resource_type_id.as_deref(), Some("type-1"));
        assert_eq!(ffi_resource.created.as_deref(), Some(CREATED));
        assert_eq!(ffi_resource.modified.as_deref(), Some(MODIFIED));
        assert_eq!(ffi_resource.created_by.as_deref(), Some("user-1"));
        assert_eq!(ffi_resource.modified_by.as_deref(), Some("user-2"));
        assert_eq!(ffi_resource.personal, Some(true));
        assert_eq!(ffi_resource.expired.as_deref(), Some(MODIFIED));
        let favorite = ffi_resource.favorite.unwrap();
        assert_eq!(favorite.id.as_deref(), Some("favorite-1"));
        assert_eq!(favorite.foreign_model.as_deref(), Some("Resource"));
        assert_eq!(favorite.foreign_key.as_deref(), Some("resource-1"));
        assert_eq!(favorite.created.as_deref(), Some(CREATED));
        let secret = &ffi_resource.secrets[0];
        assert_eq!(secret.id.as_deref(), Some("secret-1"));
        assert_eq!(secret.resource_id.as_deref(), Some("resource-1"));
        assert_eq!(secret.user_id.as_deref(), Some("user-1"));
        assert_eq!(secret.data.as_deref(), Some("PGP"));
        assert_eq!(secret.created.as_deref(), Some(CREATED));
        assert_eq!(secret.modified.as_deref(), Some(MODIFIED));
        assert_eq!(ffi_resource.permissions.len(), 1);
        assert_eq!(ffi_resource.metadata, None);
        assert_eq!(ffi_resource.metadata_key_id, None);
        assert_eq!(ffi_resource.metadata_key_type, None);
    }

    #[test]
    fn test_resource_v5_keeps_metadata_fields() {
        let resource: types::Resource = parse(json!({
            "id": "resource-1",
            "created": CREATED,
            "modified": MODIFIED,
            "metadata": "-----BEGIN PGP MESSAGE-----",
            "metadata_key_id": "metadata-key-1",
            "metadata_key_type": "shared_key"
        }));

        let ffi_resource = FfiResource::from(resource);

        assert_eq!(ffi_resource.name, "");
        assert_eq!(
            ffi_resource.metadata.as_deref(),
            Some("-----BEGIN PGP MESSAGE-----")
        );
        assert_eq!(
            ffi_resource.metadata_key_id.as_deref(),
            Some("metadata-key-1")
        );
        assert_eq!(
            ffi_resource.metadata_key_type.as_deref(),
            Some("shared_key")
        );
    }

    #[test]
    fn test_folder_keeps_every_field() {
        let folder: types::Folder = parse(folder_json("folder-2", Some("folder-1")));

        let ffi_folder = FfiFolder::from(folder);

        assert_eq!(ffi_folder.id, "folder-2");
        assert_eq!(ffi_folder.name, "folder folder-2");
        assert_eq!(ffi_folder.folder_parent_id.as_deref(), Some("folder-1"));
        assert_eq!(ffi_folder.created.as_deref(), Some(CREATED));
        assert_eq!(ffi_folder.modified.as_deref(), Some(MODIFIED));
        assert_eq!(ffi_folder.created_by.as_deref(), Some("user-1"));
        assert_eq!(ffi_folder.modified_by.as_deref(), Some("user-2"));
        assert_eq!(ffi_folder.personal, Some(false));
        assert_eq!(ffi_folder.permissions.len(), 1);
    }

    #[test]
    fn test_user_keeps_every_field_but_groups_users() {
        let user: types::User = parse(user_json("user-1"));

        let ffi_user = FfiUser::from(user);

        assert_eq!(ffi_user.id, "user-1");
        assert_eq!(ffi_user.username.as_deref(), Some("ada@passbolt.test"));
        assert_eq!(ffi_user.role_id.as_deref(), Some("role-1"));
        assert_eq!(ffi_user.created.as_deref(), Some(CREATED));
        assert_eq!(ffi_user.modified.as_deref(), Some(MODIFIED));
        assert_eq!(ffi_user.active, Some(true));
        assert_eq!(ffi_user.deleted, Some(false));
        let profile = ffi_user.profile.unwrap();
        assert_eq!(profile.first_name.as_deref(), Some("Ada"));
        assert_eq!(profile.last_name.as_deref(), Some("Lovelace"));
        let role = ffi_user.role.unwrap();
        assert_eq!(role.id.as_deref(), Some("role-1"));
        assert_eq!(role.name.as_deref(), Some("user"));
        let gpg_key = ffi_user.gpg_key.unwrap();
        assert_eq!(gpg_key.id.as_deref(), Some("key-1"));
        assert_eq!(gpg_key.user_id.as_deref(), Some("user-1"));
        assert_eq!(
            gpg_key.armored_key.as_deref(),
            Some("-----BEGIN PGP PUBLIC KEY BLOCK-----")
        );
        assert_eq!(gpg_key.bits, Some(2048));
        assert_eq!(gpg_key.fingerprint.as_deref(), Some("ABCDEF"));
        assert_eq!(gpg_key.key_created.as_deref(), Some(CREATED));
    }

    #[test]
    fn test_group_keeps_every_field_and_group_users_without_user() {
        let group: types::Group = parse(group_json());

        let ffi_group = FfiGroup::from(group);

        assert_eq!(ffi_group.id, "group-1");
        assert_eq!(ffi_group.name, "Developers");
        assert_eq!(ffi_group.created.as_deref(), Some(CREATED));
        assert_eq!(ffi_group.modified.as_deref(), Some(MODIFIED));
        assert_eq!(ffi_group.created_by.as_deref(), Some("user-1"));
        assert_eq!(ffi_group.modified_by.as_deref(), Some("user-2"));
        assert_eq!(ffi_group.deleted, Some(false));
        let group_user = &ffi_group.groups_users[0];
        assert_eq!(group_user.id.as_deref(), Some("gu-1"));
        assert_eq!(group_user.group_id.as_deref(), Some("group-1"));
        assert_eq!(group_user.user_id.as_deref(), Some("user-1"));
        assert_eq!(group_user.is_admin, Some(true));
        assert_eq!(group_user.created.as_deref(), Some(CREATED));
    }

    #[test]
    fn test_permission_converts_nested_user_and_group() {
        let permission: types::Permission = parse(permission_json());

        let ffi_permission = FfiPermission::from(permission);

        assert_eq!(ffi_permission.id.as_deref(), Some("permission-1"));
        assert_eq!(ffi_permission.aco.as_deref(), Some("Resource"));
        assert_eq!(
            ffi_permission.aco_foreign_key.as_deref(),
            Some("resource-1")
        );
        assert_eq!(ffi_permission.aro.as_deref(), Some("User"));
        assert_eq!(ffi_permission.aro_foreign_key.as_deref(), Some("user-1"));
        assert_eq!(ffi_permission.permission_type, Some(15));
        assert_eq!(ffi_permission.created.as_deref(), Some(CREATED));
        assert_eq!(ffi_permission.modified.as_deref(), Some(MODIFIED));
        let user = ffi_permission.user.unwrap();
        assert_eq!(user.id, "user-1");
        assert_eq!(user.gpg_key.unwrap().fingerprint.as_deref(), Some("ABCDEF"));
        let group = ffi_permission.group.unwrap();
        assert_eq!(group.id, "group-1");
        assert_eq!(group.groups_users[0].user_id.as_deref(), Some("user-1"));
    }

    #[test]
    fn test_secret_data_keeps_password_totp_and_raw() {
        let secret_data = types::SecretData {
            password: Some("hunter2".into()),
            description: Some("note".into()),
            totp: Some(parse(json!({
                "secret_key": "JBSWY3DPEHPK3PXP",
                "algorithm": "SHA1",
                "digits": 6,
                "period": 30,
                "issuer": "Passbolt"
            }))),
            raw: Some("raw secret".into()),
            ..types::SecretData::default()
        };

        let ffi_secret_data = FfiSecretData::from(secret_data);

        assert_eq!(ffi_secret_data.password.as_deref(), Some("hunter2"));
        assert_eq!(ffi_secret_data.description.as_deref(), Some("note"));
        assert_eq!(ffi_secret_data.raw.as_deref(), Some("raw secret"));
        let totp = ffi_secret_data.totp.unwrap();
        assert_eq!(totp.secret_key.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert_eq!(totp.algorithm.as_deref(), Some("SHA1"));
        assert_eq!(totp.digits, Some(6));
        assert_eq!(totp.period, Some(30));
        assert_eq!(totp.issuer.as_deref(), Some("Passbolt"));
    }

    #[test]
    fn test_tag_keeps_every_field() {
        let tag: types::Tag = parse(json!({
            "id": "tag-1", "slug": "#prod", "is_shared": true, "created": CREATED, "modified": MODIFIED
        }));

        let ffi_tag = FfiTag::from(tag);

        assert_eq!(ffi_tag.id, "tag-1");
        assert_eq!(ffi_tag.slug, "#prod");
        assert_eq!(ffi_tag.is_shared, Some(true));
        assert_eq!(ffi_tag.created.as_deref(), Some(CREATED));
        assert_eq!(ffi_tag.modified.as_deref(), Some(MODIFIED));
    }

    #[test]
    fn test_comment_keeps_every_field_and_converts_creator() {
        let comment: types::Comment = parse(json!({
            "id": "comment-1",
            "parent_id": "comment-0",
            "foreign_key": "resource-1",
            "foreign_model": "Resource",
            "content": "hello",
            "created": CREATED,
            "modified": MODIFIED,
            "created_by": "user-1",
            "modified_by": "user-2",
            "creator": user_json("user-1")
        }));

        let ffi_comment = FfiComment::from(comment);

        assert_eq!(ffi_comment.id, "comment-1");
        assert_eq!(ffi_comment.parent_id.as_deref(), Some("comment-0"));
        assert_eq!(ffi_comment.foreign_key.as_deref(), Some("resource-1"));
        assert_eq!(ffi_comment.foreign_model.as_deref(), Some("Resource"));
        assert_eq!(ffi_comment.content, "hello");
        assert_eq!(ffi_comment.created.as_deref(), Some(CREATED));
        assert_eq!(ffi_comment.modified.as_deref(), Some(MODIFIED));
        assert_eq!(ffi_comment.created_by.as_deref(), Some("user-1"));
        assert_eq!(ffi_comment.modified_by.as_deref(), Some("user-2"));
        let creator = ffi_comment.creator.unwrap();
        assert_eq!(creator.id, "user-1");
        assert_eq!(creator.profile.unwrap().first_name.as_deref(), Some("Ada"));
    }

    #[rstest]
    #[case::user(
        json!({ "id": "user-1", "type": "user", "username": "ada", "profile": { "first_name": "Ada", "last_name": "L" } }),
        Some("user"), Some("ada"), true, None
    )]
    #[case::group(
        json!({ "id": "group-1", "type": "group", "name": "Developers" }),
        Some("group"), None, false, Some("Developers")
    )]
    fn test_aro_keeps_every_field(
        #[case] aro_json: Value,
        #[case] expected_type: Option<&str>,
        #[case] expected_username: Option<&str>,
        #[case] expected_profile: bool,
        #[case] expected_name: Option<&str>,
    ) {
        let aro: types::Aro = parse(aro_json);

        let ffi_aro = FfiAro::from(aro);

        assert_eq!(ffi_aro.aro_type.as_deref(), expected_type);
        assert_eq!(ffi_aro.username.as_deref(), expected_username);
        assert_eq!(ffi_aro.profile.is_some(), expected_profile);
        assert_eq!(ffi_aro.name.as_deref(), expected_name);
    }

    #[test]
    fn test_password_expiry_settings_keeps_every_field() {
        let settings: types::PasswordExpirySettings = parse(json!({
            "id": "settings-1",
            "default_expiry_period": 90,
            "policy_override": true,
            "automatic_expiry": false,
            "automatic_update": true
        }));

        let ffi_settings = FfiPasswordExpirySettings::from(settings);

        assert_eq!(ffi_settings.id.as_deref(), Some("settings-1"));
        assert_eq!(ffi_settings.default_expiry_period_days, Some(90));
        assert_eq!(ffi_settings.policy_override, Some(true));
        assert_eq!(ffi_settings.automatic_expiry, Some(false));
        assert_eq!(ffi_settings.automatic_update, Some(true));
    }

    #[test]
    fn test_delete_dry_runs_keep_every_count() {
        let user_dry_run: types::UserDeleteDryRun = parse(json!({
            "resources_sole_owner_count": 1,
            "folders_sole_owner_count": 2,
            "groups_sole_manager_count": 3
        }));
        let group_dry_run: types::GroupDeleteDryRun = parse(json!({
            "resources_sole_group_count": 4,
            "folders_sole_group_count": 5
        }));

        let ffi_user_dry_run = FfiUserDeleteDryRun::from(user_dry_run);
        let ffi_group_dry_run = FfiGroupDeleteDryRun::from(group_dry_run);

        assert_eq!(ffi_user_dry_run.resources_sole_owner_count, 1);
        assert_eq!(ffi_user_dry_run.folders_sole_owner_count, 2);
        assert_eq!(ffi_user_dry_run.groups_sole_manager_count, 3);
        assert_eq!(ffi_group_dry_run.resources_sole_group_count, 4);
        assert_eq!(ffi_group_dry_run.folders_sole_group_count, 5);
    }

    #[test]
    fn test_folder_tree_converts_children_recursively() {
        let leaf = types::FolderTreeNode {
            folder: parse(folder_json("leaf", Some("middle"))),
            children: Vec::new(),
        };
        let middle = types::FolderTreeNode {
            folder: parse(folder_json("middle", Some("root"))),
            children: vec![leaf],
        };
        let root = types::FolderTreeNode {
            folder: parse(folder_json("root", None)),
            children: vec![middle],
        };

        let ffi_root = FfiFolderTreeNode::from(root);

        assert_eq!(ffi_root.folder.id, "root");
        let ffi_middle = &ffi_root.children[0];
        assert_eq!(ffi_middle.folder.id, "middle");
        assert_eq!(ffi_middle.children[0].folder.id, "leaf");
        assert!(ffi_middle.children[0].children.is_empty());
    }

    #[test]
    fn test_resource_query_sets_filters_and_defaults_the_rest() {
        let query = passbolt_sdk::ResourceQuery::from(FfiResourceQuery {
            search: Some("mail".into()),
            favorites_only: true,
            owned_by_me: true,
        });

        assert_eq!(query.search.as_deref(), Some("mail"));
        assert!(query.favorites_only);
        assert!(query.owned_by_me);
        assert_eq!(query.group_ids, Vec::<String>::new());
        assert_eq!(query.folder_ids, Vec::<String>::new());
        assert_eq!(query.pagination.page, None);
        assert_eq!(query.pagination.limit, None);
    }

    #[test]
    fn test_folder_query_sets_search_and_defaults_the_rest() {
        let query = passbolt_sdk::FolderQuery::from(FfiFolderQuery {
            search: Some("ops".into()),
        });

        assert_eq!(query.search.as_deref(), Some("ops"));
        assert_eq!(query.group_id, None);
        assert_eq!(query.parent_folder_ids, Vec::<String>::new());
        assert_eq!(query.pagination.page, None);
    }

    #[test]
    fn test_user_query_sets_filters_and_defaults_the_rest() {
        let query = passbolt_sdk::UserQuery::from(FfiUserQuery {
            search: Some("ada".into()),
            group_id: Some("group-1".into()),
            admin_only: true,
        });

        assert_eq!(query.search.as_deref(), Some("ada"));
        assert_eq!(query.group_id.as_deref(), Some("group-1"));
        assert!(query.admin_only);
        assert_eq!(query.resource_id, None);
        assert_eq!(query.pagination.page, None);
    }
}
