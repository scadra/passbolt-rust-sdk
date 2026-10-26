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

//! The JSON go-passbolt-cli prints, field for field: scripts written for it read ours.

use chrono::{DateTime, SecondsFormat, Utc};
use passbolt_sdk::resource::view::ResourceView;
use passbolt_sdk::types::{Folder, Group, GroupUser, Permission, User};
use serde::Serialize;
use serde_json::{Map, Value};

/// A date as Go writes it in JSON; a missing one is Go's zero time.
pub fn json_time(date: Option<DateTime<Utc>>) -> String {
    date.map_or_else(
        || "0001-01-01T00:00:00Z".to_string(),
        |date| date.to_rfc3339_opts(SecondsFormat::AutoSi, true),
    )
}

/// A date as go-passbolt-cli writes it in a table cell (RFC 3339, to the second).
pub fn table_time(date: Option<DateTime<Utc>>) -> String {
    date.map_or_else(
        || "0001-01-01T00:00:00Z".to_string(),
        |date| date.to_rfc3339_opts(SecondsFormat::Secs, true),
    )
}

/// The metadata fields go-passbolt reads from a resource: the decrypted v5 metadata as it is,
/// or the v4 fields; `uri` is the first of `uris` when absent, and an empty description is
/// taken from the secret.
pub fn resource_metadata(view: &ResourceView) -> Map<String, Value> {
    let mut fields = if view.is_v5() {
        let mut fields = view.metadata.clone();
        fields.insert("object_type".into(), "PASSBOLT_RESOURCE_METADATA".into());
        if let Some(resource_type_id) = &view.resource_type_id {
            fields.insert("resource_type_id".into(), resource_type_id.clone().into());
        }
        fields
    } else {
        let resource = &view.resource;
        Map::from_iter([
            ("name".to_string(), resource.name.clone().into()),
            (
                "username".to_string(),
                resource.username.clone().unwrap_or_default().into(),
            ),
            (
                "uri".to_string(),
                resource.uri.clone().unwrap_or_default().into(),
            ),
            (
                "description".to_string(),
                resource.description.clone().unwrap_or_default().into(),
            ),
        ])
    };
    if !fields.contains_key("uri") {
        fields.insert(
            "uri".into(),
            view.uris.first().cloned().unwrap_or_default().into(),
        );
    }
    if fields
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .is_empty()
    {
        let from_secret = view
            .secret
            .as_ref()
            .and_then(|secret| secret.get("description"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        fields.insert("description".into(), from_secret.into());
    }
    fields
}

/// The text field `key` of go-passbolt's metadata fields.
pub fn metadata_text(fields: &Map<String, Value>, key: &str) -> String {
    fields
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

#[derive(Serialize)]
pub struct ResourceJson {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder_parent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_timestamp: Option<String>,
    #[serde(skip_serializing_if = "Map::is_empty")]
    pub metadata: Map<String, Value>,
    #[serde(skip_serializing_if = "Map::is_empty")]
    pub secret: Map<String, Value>,
    pub deleted: bool,
    pub expired: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expired_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_type_id: Option<String>,
}

/// A resource of `list resource --json`.
pub fn listed_resource(view: &ResourceView) -> ResourceJson {
    ResourceJson {
        id: Some(view.id.clone()),
        created_timestamp: Some(json_time(view.created)),
        modified_timestamp: Some(json_time(view.modified)),
        deleted: view.resource.deleted.unwrap_or(false),
        expired: view.expired.is_some(),
        expired_at: view.expired.map(|date| json_time(Some(date))),
        resource_type_id: Some(view.resource_type_id.clone().unwrap_or_default()),
        ..got_resource(view)
    }
}

/// The resource of `get resource --json`: no id, no dates, never deleted nor expired.
pub fn got_resource(view: &ResourceView) -> ResourceJson {
    let metadata = resource_metadata(view);
    ResourceJson {
        id: None,
        folder_parent_id: Some(view.folder_parent_id.clone().unwrap_or_default()),
        name: Some(metadata_text(&metadata, "name")),
        username: Some(metadata_text(&metadata, "username")),
        uri: Some(metadata_text(&metadata, "uri")),
        password: Some(view.password.clone().unwrap_or_default()),
        description: Some(metadata_text(&metadata, "description")),
        created_timestamp: None,
        modified_timestamp: None,
        secret: view.secret.clone().unwrap_or_default(),
        metadata,
        deleted: false,
        expired: false,
        expired_at: None,
        resource_type_id: None,
    }
}

#[derive(Serialize)]
pub struct FolderJson {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder_parent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_timestamp: Option<String>,
    pub personal: bool,
}

pub fn listed_folder(folder: &Folder) -> FolderJson {
    FolderJson {
        id: Some(folder.id.clone()),
        created_timestamp: Some(json_time(folder.created)),
        modified_timestamp: Some(json_time(folder.modified)),
        personal: folder.personal.unwrap_or(false),
        ..got_folder(folder)
    }
}

/// The folder of `get folder --json`: its parent and name.
pub fn got_folder(folder: &Folder) -> FolderJson {
    FolderJson {
        id: None,
        folder_parent_id: Some(folder.folder_parent_id.clone().unwrap_or_default()),
        name: Some(folder.name.clone()),
        created_timestamp: None,
        modified_timestamp: None,
        personal: false,
    }
}

#[derive(Serialize)]
pub struct UserJson {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_timestamp: Option<String>,
    pub active: bool,
    pub deleted: bool,
    pub disabled: bool,
}

pub fn listed_user(user: &User) -> UserJson {
    UserJson {
        id: Some(user.id.clone()),
        created_timestamp: Some(json_time(user.created)),
        modified_timestamp: Some(json_time(user.modified)),
        active: user.active.unwrap_or(false),
        deleted: user.deleted.unwrap_or(false),
        disabled: user.disabled.is_some(),
        ..got_user(user)
    }
}

/// The user of `get user --json`: names and role.
pub fn got_user(user: &User) -> UserJson {
    UserJson {
        id: None,
        username: Some(user.username.clone().unwrap_or_default()),
        first_name: Some(user.first_name().to_string()),
        last_name: Some(user.last_name().to_string()),
        role: Some(user.role_name().to_string()),
        created_timestamp: None,
        modified_timestamp: None,
        active: false,
        deleted: false,
        disabled: false,
    }
}

#[derive(Serialize)]
pub struct GroupJson {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<GroupMemberJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_timestamp: Option<String>,
    pub deleted: bool,
    pub user_count: usize,
}

#[derive(Serialize)]
pub struct GroupMemberJson {
    pub id: String,
    pub username: String,
    pub first_name: String,
    pub last_name: String,
    pub is_group_manager: bool,
}

pub fn listed_group(group: &Group) -> GroupJson {
    GroupJson {
        id: Some(group.id.clone()),
        name: Some(group.name.clone()),
        users: Vec::new(),
        created_timestamp: Some(json_time(group.created)),
        modified_timestamp: Some(json_time(group.modified)),
        deleted: group.deleted.unwrap_or(false),
        user_count: group.groups_users.len(),
    }
}

/// The group of `get group --json`: its name and members.
pub fn got_group(group: &Group) -> GroupJson {
    GroupJson {
        id: None,
        name: Some(group.name.clone()),
        users: group.groups_users.iter().map(group_member).collect(),
        created_timestamp: None,
        modified_timestamp: None,
        deleted: false,
        user_count: 0,
    }
}

fn group_member(member: &GroupUser) -> GroupMemberJson {
    let user = member.user.as_deref();
    GroupMemberJson {
        id: member.user_id.clone().unwrap_or_default(),
        username: user
            .and_then(|user| user.username.clone())
            .unwrap_or_default(),
        first_name: user.map(User::first_name).unwrap_or_default().to_string(),
        last_name: user.map(User::last_name).unwrap_or_default().to_string(),
        is_group_manager: member.is_admin.unwrap_or(false),
    }
}

#[derive(Serialize)]
pub struct PermissionJson {
    pub id: String,
    pub aco: String,
    pub aco_foreign_key: String,
    pub aro: String,
    pub aro_foreign_key: String,
    #[serde(rename = "type")]
    pub permission_type: i32,
    pub created_timestamp: String,
    pub modified_timestamp: String,
}

pub fn permission(permission: &Permission) -> PermissionJson {
    let text = |value: &Option<String>| value.clone().unwrap_or_default();
    PermissionJson {
        id: text(&permission.id),
        aco: text(&permission.aco),
        aco_foreign_key: text(&permission.aco_foreign_key),
        aro: text(&permission.aro),
        aro_foreign_key: text(&permission.aro_foreign_key),
        permission_type: permission.permission_type.unwrap_or(0),
        created_timestamp: json_time(permission.created),
        modified_timestamp: json_time(permission.modified),
    }
}

/// The permission type as go-passbolt-cli names it: `read`, `update`, `owner`, else its number.
pub fn permission_type_name(permission_type: Option<i32>) -> String {
    match permission_type.unwrap_or(0) {
        1 => "read".into(),
        7 => "update".into(),
        15 => "owner".into(),
        other => other.to_string(),
    }
}

/// `value` as Go's `fmt.Sprint` prints decoded JSON: `[a b]`, `map[k:v]`, `<nil>`.
pub fn go_sprint(value: &Value) -> String {
    match value {
        Value::Null => "<nil>".into(),
        Value::String(text) => text.clone(),
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => number.to_string(),
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(go_sprint).collect::<Vec<_>>().join(" ")
        ),
        Value::Object(fields) => format!(
            "map[{}]",
            fields
                .iter()
                .map(|(key, value)| format!("{key}:{}", go_sprint(value)))
                .collect::<Vec<_>>()
                .join(" ")
        ),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn test_times_are_written_as_go_writes_them() {
        let date = DateTime::parse_from_rfc3339("2024-01-01T10:00:00+00:00")
            .unwrap()
            .to_utc();

        assert_eq!(json_time(Some(date)), "2024-01-01T10:00:00Z");
        assert_eq!(table_time(Some(date)), "2024-01-01T10:00:00Z");
        assert_eq!(json_time(None), "0001-01-01T00:00:00Z");
    }

    #[test]
    fn test_go_sprint_writes_lists_and_maps_as_go() {
        let value = json!({"b": [1, "x"], "a": null, "c": {"d": true}});

        assert_eq!(go_sprint(&value), "map[a:<nil> b:[1 x] c:map[d:true]]");
    }

    #[rstest::rstest]
    #[case(Some(1), "read")]
    #[case(Some(7), "update")]
    #[case(Some(15), "owner")]
    #[case(Some(3), "3")]
    fn test_permission_types_are_named_as_go_names_them(
        #[case] permission_type: Option<i32>,
        #[case] name: &str,
    ) {
        assert_eq!(permission_type_name(permission_type), name);
    }

    #[test]
    fn test_a_listed_user_is_flat_with_its_role_name() {
        let user: User = serde_json::from_value(json!({
            "id": "u1",
            "username": "ada@passbolt.test",
            "created": "2024-01-01T10:00:00+00:00",
            "modified": "2024-01-02T10:00:00+00:00",
            "active": true,
            "deleted": false,
            "disabled": null,
            "profile": {"first_name": "Ada", "last_name": "Lovelace"},
            "role": {"id": "r1", "name": "admin"}
        }))
        .unwrap();

        assert_eq!(
            serde_json::to_string(&listed_user(&user)).unwrap(),
            r#"{"id":"u1","username":"ada@passbolt.test","first_name":"Ada","last_name":"Lovelace","role":"admin","created_timestamp":"2024-01-01T10:00:00Z","modified_timestamp":"2024-01-02T10:00:00Z","active":true,"deleted":false,"disabled":false}"#
        );
    }

    #[test]
    fn test_a_folder_at_the_root_has_an_empty_parent() {
        let folder: Folder = serde_json::from_value(json!({"id": "f1", "name": "Ops"})).unwrap();

        assert_eq!(
            serde_json::to_value(got_folder(&folder)).unwrap(),
            json!({"folder_parent_id": "", "name": "Ops", "personal": false})
        );
    }
}
