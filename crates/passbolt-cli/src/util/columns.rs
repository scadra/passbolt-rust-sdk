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

//! The columns of the lists, of `get group` and of the permissions, named, ordered and printed
//! as go-passbolt-cli does.

use anyhow::{bail, Result};
use passbolt_sdk::resource::view::ResourceView;
use passbolt_sdk::types::{Folder, Group, GroupUser, Permission, User};
use serde::Serialize;
use serde_json::{Map, Value};

use std::collections::HashMap;

use crate::util::cel::{zero_timestamp, CelValue, Kind, Variable};
use crate::util::output;
use crate::util::shapes::{self, metadata_text, permission_type_name, table_time};

/// A column: its canonical name, the other spellings it accepts, and its value.
pub struct Column<T> {
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    /// Shown when no column is asked for.
    pub default: bool,
    /// Its value needs the secrets decrypted.
    pub secret: bool,
    /// Not a go-passbolt-cli column: absent from the full JSON, added when asked for.
    pub extension: bool,
    pub value: fn(&T) -> Value,
}

/// The columns of one kind of item.
pub struct Columns<T: 'static> {
    /// The items, plural, for the error of a filter matching nothing.
    pub noun: &'static str,
    pub columns: &'static [Column<T>],
}

/// Lower case, without `_`, `-` or spaces: `First Name`, `first_name` and `FirstName` match.
fn compact(name: &str) -> String {
    name.chars()
        .filter(|character| !matches!(character, '_' | '-' | ' '))
        .collect::<String>()
        .to_lowercase()
}

impl<T> Columns<T> {
    /// The column named `name` in any spelling go-passbolt-cli accepts, or ours.
    pub fn find(&self, name: &str) -> Result<&'static Column<T>> {
        let wanted = compact(name);
        self.columns
            .iter()
            .find(|column| {
                compact(column.name) == wanted
                    || column.aliases.iter().any(|alias| compact(alias) == wanted)
            })
            .map_or_else(
                || {
                    let valid: Vec<&str> = self.columns.iter().map(|column| column.name).collect();
                    bail!("unknown column: {name:?} (valid: {})", valid.join(", "))
                },
                Ok,
            )
    }

    /// The columns named by `requested`, or the default ones when none is.
    pub fn select(&self, requested: &[String]) -> Result<Vec<&'static Column<T>>> {
        if requested.is_empty() {
            return Ok(self
                .columns
                .iter()
                .filter(|column| column.default)
                .collect());
        }
        requested.iter().map(|name| self.find(name)).collect()
    }

    /// The columns `read` of `item`, typed as `variables` declare them for a CEL filter.
    pub fn cel_row(
        &self,
        variables: &[Variable],
        read: &[&str],
        item: &T,
    ) -> HashMap<&'static str, CelValue> {
        self.columns
            .iter()
            .filter(|column| read.contains(&column.name))
            .filter_map(|column| {
                let kind = variables
                    .iter()
                    .find(|variable| variable.column == column.name)?
                    .kind;
                let value = (column.value)(item);
                let typed = match kind {
                    Kind::String => CelValue::String(cell(value)),
                    Kind::Bool => CelValue::Bool(value.as_bool().unwrap_or(false)),
                    Kind::Int => CelValue::Int(value.as_i64().unwrap_or(0)),
                    Kind::Timestamp => CelValue::Timestamp(
                        value
                            .as_str()
                            .and_then(|text| chrono::DateTime::parse_from_rfc3339(text).ok())
                            .map_or_else(zero_timestamp, |date| date.to_utc()),
                    ),
                    Kind::Map => CelValue::Map(match value {
                        Value::Object(fields) => fields,
                        _ => Map::new(),
                    }),
                };
                Some((column.name, typed))
            })
            .collect()
    }

    /// Print `items`: a table of the selected columns, or JSON. Without requested columns the
    /// JSON holds each item as go-passbolt-cli writes it (`json`), else only the requested
    /// keys of it.
    pub fn print<J: Serialize>(
        &self,
        items: &[T],
        requested: &[String],
        json: fn(&T) -> J,
        json_output: bool,
    ) -> Result<()> {
        let selected = self.select(requested)?;
        if !json_output {
            let headers: Vec<&str> = selected.iter().map(|column| column.name).collect();
            let rows = items
                .iter()
                .map(|item| {
                    selected
                        .iter()
                        .map(|column| cell((column.value)(item)))
                        .collect()
                })
                .collect();
            output::print_table(&headers, rows);
            return Ok(());
        }
        if requested.is_empty() {
            let objects: Vec<J> = items.iter().map(json).collect();
            return output::print_json(&objects);
        }
        let objects = items
            .iter()
            .map(|item| {
                let Value::Object(full) = serde_json::to_value(json(item))? else {
                    bail!("an item is not a JSON object");
                };
                Ok(selected
                    .iter()
                    .filter_map(|column| {
                        let value = full
                            .get(column.name)
                            .cloned()
                            .or_else(|| column.extension.then(|| (column.value)(item)))?;
                        Some((column.name.to_string(), value))
                    })
                    .collect::<Map<String, Value>>())
            })
            .collect::<Result<Vec<_>>>()?;
        output::print_json(&objects)
    }
}

/// A value as go-passbolt-cli writes it in a cell: text as it is, an empty map as nothing, a
/// map as compact JSON, a list of texts joined.
pub fn cell(value: Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(text) => text,
        Value::Object(fields) if fields.is_empty() => String::new(),
        Value::Array(items) if items.iter().all(Value::is_string) => items
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(", "),
        value => value.to_string(),
    }
}

fn time(date: Option<chrono::DateTime<chrono::Utc>>) -> Value {
    table_time(date).into()
}

pub const RESOURCES: Columns<ResourceView> = Columns {
    noun: "resources",
    columns: &[
        Column {
            name: "id",
            aliases: &["ID"],
            default: true,
            secret: false,
            extension: false,
            value: |view| view.id.clone().into(),
        },
        Column {
            name: "folder_parent_id",
            aliases: &["FolderParentID", "parent", "parent_id"],
            default: true,
            secret: false,
            extension: false,
            value: |view| view.folder_parent_id.clone().unwrap_or_default().into(),
        },
        Column {
            name: "name",
            aliases: &["Name"],
            default: true,
            secret: false,
            extension: false,
            value: |view| metadata_text(&shapes::resource_metadata(view), "name").into(),
        },
        Column {
            name: "username",
            aliases: &["Username"],
            default: true,
            secret: false,
            extension: false,
            value: |view| metadata_text(&shapes::resource_metadata(view), "username").into(),
        },
        Column {
            name: "uri",
            aliases: &["URI", "url"],
            default: true,
            secret: false,
            extension: false,
            value: |view| metadata_text(&shapes::resource_metadata(view), "uri").into(),
        },
        Column {
            name: "password",
            aliases: &["Password"],
            default: false,
            secret: true,
            extension: false,
            value: |view| view.password.clone().unwrap_or_default().into(),
        },
        Column {
            name: "description",
            aliases: &["Description"],
            default: false,
            secret: true,
            extension: false,
            value: |view| metadata_text(&shapes::resource_metadata(view), "description").into(),
        },
        Column {
            name: "created_timestamp",
            aliases: &["CreatedTimestamp", "created"],
            default: false,
            secret: false,
            extension: false,
            value: |view| time(view.created),
        },
        Column {
            name: "modified_timestamp",
            aliases: &["ModifiedTimestamp", "modified"],
            default: false,
            secret: false,
            extension: false,
            value: |view| time(view.modified),
        },
        Column {
            name: "metadata",
            aliases: &["Metadata"],
            default: false,
            secret: false,
            extension: false,
            value: |view| Value::Object(shapes::resource_metadata(view)),
        },
        Column {
            name: "secret",
            aliases: &["Secret"],
            default: false,
            secret: true,
            extension: false,
            value: |view| Value::Object(view.secret.clone().unwrap_or_default()),
        },
        Column {
            name: "deleted",
            aliases: &["Deleted"],
            default: false,
            secret: false,
            extension: false,
            value: |view| view.resource.deleted.unwrap_or(false).into(),
        },
        Column {
            name: "expired",
            aliases: &["Expired"],
            default: false,
            secret: false,
            extension: false,
            value: |view| view.expired.is_some().into(),
        },
        Column {
            name: "expired_at",
            aliases: &["ExpiredAt", "expiry"],
            default: false,
            secret: false,
            extension: false,
            value: |view| {
                view.expired
                    .map_or_else(String::new, |date| table_time(Some(date)))
                    .into()
            },
        },
        Column {
            name: "resource_type_id",
            aliases: &["ResourceTypeID"],
            default: false,
            secret: false,
            extension: false,
            value: |view| view.resource_type_id.clone().unwrap_or_default().into(),
        },
        Column {
            name: "uris",
            aliases: &[],
            default: false,
            secret: false,
            extension: true,
            value: |view| view.uris.clone().into(),
        },
        Column {
            name: "note",
            aliases: &[],
            default: false,
            secret: true,
            extension: true,
            value: |view| view.note().unwrap_or_default().into(),
        },
        Column {
            name: "resource_type",
            aliases: &["type"],
            default: false,
            secret: false,
            extension: true,
            value: |view| view.resource_type.clone().unwrap_or_default().into(),
        },
        Column {
            name: "personal",
            aliases: &[],
            default: false,
            secret: false,
            extension: true,
            value: |view| view.personal.unwrap_or(false).into(),
        },
    ],
};

pub const FOLDERS: Columns<Folder> = Columns {
    noun: "folders",
    columns: &[
        Column {
            name: "id",
            aliases: &["ID"],
            default: true,
            secret: false,
            extension: false,
            value: |folder| folder.id.clone().into(),
        },
        Column {
            name: "folder_parent_id",
            aliases: &["FolderParentID", "parent", "parent_id"],
            default: true,
            secret: false,
            extension: false,
            value: |folder| folder.folder_parent_id.clone().unwrap_or_default().into(),
        },
        Column {
            name: "name",
            aliases: &["Name"],
            default: true,
            secret: false,
            extension: false,
            value: |folder| folder.name.clone().into(),
        },
        Column {
            name: "created_timestamp",
            aliases: &["CreatedTimestamp", "created"],
            default: false,
            secret: false,
            extension: false,
            value: |folder| time(folder.created),
        },
        Column {
            name: "modified_timestamp",
            aliases: &["ModifiedTimestamp", "modified"],
            default: false,
            secret: false,
            extension: false,
            value: |folder| time(folder.modified),
        },
        Column {
            name: "personal",
            aliases: &["Personal"],
            default: false,
            secret: false,
            extension: false,
            value: |folder| folder.personal.unwrap_or(false).into(),
        },
    ],
};

pub const USERS: Columns<User> = Columns {
    noun: "users",
    columns: &[
        Column {
            name: "id",
            aliases: &["ID"],
            default: true,
            secret: false,
            extension: false,
            value: |user| user.id.clone().into(),
        },
        Column {
            name: "username",
            aliases: &["Username"],
            default: true,
            secret: false,
            extension: false,
            value: |user| user.username.clone().unwrap_or_default().into(),
        },
        Column {
            name: "first_name",
            aliases: &["FirstName"],
            default: true,
            secret: false,
            extension: false,
            value: |user| user.first_name().into(),
        },
        Column {
            name: "last_name",
            aliases: &["LastName"],
            default: true,
            secret: false,
            extension: false,
            value: |user| user.last_name().into(),
        },
        Column {
            name: "role",
            aliases: &["Role"],
            default: true,
            secret: false,
            extension: false,
            value: |user| user.role_name().into(),
        },
        Column {
            name: "created_timestamp",
            aliases: &["CreatedTimestamp", "created"],
            default: false,
            secret: false,
            extension: false,
            value: |user| time(user.created),
        },
        Column {
            name: "modified_timestamp",
            aliases: &["ModifiedTimestamp", "modified"],
            default: false,
            secret: false,
            extension: false,
            value: |user| time(user.modified),
        },
        Column {
            name: "active",
            aliases: &["Active"],
            default: false,
            secret: false,
            extension: false,
            value: |user| user.active.unwrap_or(false).into(),
        },
        Column {
            name: "deleted",
            aliases: &["Deleted"],
            default: false,
            secret: false,
            extension: false,
            value: |user| user.deleted.unwrap_or(false).into(),
        },
        Column {
            name: "disabled",
            aliases: &["Disabled"],
            default: false,
            secret: false,
            extension: false,
            value: |user| user.disabled.is_some().into(),
        },
    ],
};

pub const GROUPS: Columns<Group> = Columns {
    noun: "groups",
    columns: &[
        Column {
            name: "id",
            aliases: &["ID"],
            default: true,
            secret: false,
            extension: false,
            value: |group| group.id.clone().into(),
        },
        Column {
            name: "name",
            aliases: &["Name"],
            default: true,
            secret: false,
            extension: false,
            value: |group| group.name.clone().into(),
        },
        Column {
            name: "created_timestamp",
            aliases: &["CreatedTimestamp", "created"],
            default: false,
            secret: false,
            extension: false,
            value: |group| time(group.created),
        },
        Column {
            name: "modified_timestamp",
            aliases: &["ModifiedTimestamp", "modified"],
            default: false,
            secret: false,
            extension: false,
            value: |group| time(group.modified),
        },
        Column {
            name: "deleted",
            aliases: &["Deleted"],
            default: false,
            secret: false,
            extension: false,
            value: |group| group.deleted.unwrap_or(false).into(),
        },
        Column {
            name: "user_count",
            aliases: &["UserCount", "members"],
            default: false,
            secret: false,
            extension: false,
            value: |group| group.groups_users.len().into(),
        },
    ],
};

/// A column of `get group` or of the permissions: go-passbolt-cli heads it with the name as
/// it was typed.
pub struct NamedColumn<T> {
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    pub text: fn(&T) -> String,
}

/// Print `items` as a table of the `requested` columns (`defaults` without), headed as typed.
pub fn print_named<T>(
    items: &[T],
    columns: &[NamedColumn<T>],
    requested: &[String],
    defaults: &[&str],
) -> Result<()> {
    let names: Vec<&str> = if requested.is_empty() {
        defaults.to_vec()
    } else {
        requested.iter().map(String::as_str).collect()
    };
    let selected = names
        .iter()
        .map(|name| {
            let wanted = compact(name);
            columns
                .iter()
                .find(|column| {
                    compact(column.name) == wanted
                        || column.aliases.iter().any(|alias| compact(alias) == wanted)
                })
                .ok_or_else(|| anyhow::anyhow!("unknown Column: {name}"))
        })
        .collect::<Result<Vec<_>>>()?;
    let rows = items
        .iter()
        .map(|item| selected.iter().map(|column| (column.text)(item)).collect())
        .collect();
    output::print_table(&names, rows);
    Ok(())
}

/// The members of `get group`.
pub const GROUP_MEMBER_DEFAULTS: [&str; 5] = [
    "UserID",
    "Username",
    "UserFirstName",
    "UserLastName",
    "IsGroupManager",
];
pub const GROUP_MEMBERS: [NamedColumn<GroupUser>; 5] = [
    NamedColumn {
        name: "UserID",
        aliases: &[],
        text: |member| member.user_id.clone().unwrap_or_default(),
    },
    NamedColumn {
        name: "Username",
        aliases: &[],
        text: |member| {
            member
                .user
                .as_ref()
                .and_then(|user| user.username.clone())
                .unwrap_or_default()
        },
    },
    NamedColumn {
        name: "UserFirstName",
        aliases: &["first_name"],
        text: |member| {
            member
                .user
                .as_ref()
                .map(|user| user.first_name().to_string())
                .unwrap_or_default()
        },
    },
    NamedColumn {
        name: "UserLastName",
        aliases: &["last_name"],
        text: |member| {
            member
                .user
                .as_ref()
                .map(|user| user.last_name().to_string())
                .unwrap_or_default()
        },
    },
    NamedColumn {
        name: "IsGroupManager",
        aliases: &["manager", "role"],
        text: |member| member.is_admin.unwrap_or(false).to_string(),
    },
];

/// The permissions of `get resource|folder permission`.
pub const PERMISSION_DEFAULTS: [&str; 6] =
    ["ID", "Aco", "AcoForeignKey", "Aro", "AroForeignKey", "Type"];
pub const PERMISSIONS: [NamedColumn<Permission>; 8] = [
    NamedColumn {
        name: "ID",
        aliases: &[],
        text: |permission| permission.id.clone().unwrap_or_default(),
    },
    NamedColumn {
        name: "Aco",
        aliases: &[],
        text: |permission| permission.aco.clone().unwrap_or_default(),
    },
    NamedColumn {
        name: "AcoForeignKey",
        aliases: &[],
        text: |permission| permission.aco_foreign_key.clone().unwrap_or_default(),
    },
    NamedColumn {
        name: "Aro",
        aliases: &[],
        text: |permission| permission.aro.clone().unwrap_or_default(),
    },
    NamedColumn {
        name: "AroForeignKey",
        aliases: &["aro_id"],
        text: |permission| permission.aro_foreign_key.clone().unwrap_or_default(),
    },
    NamedColumn {
        name: "Type",
        aliases: &["permission_type"],
        text: |permission| permission_type_name(permission.permission_type),
    },
    NamedColumn {
        name: "CreatedTimestamp",
        aliases: &["created"],
        text: |permission| table_time(permission.created),
    },
    NamedColumn {
        name: "ModifiedTimestamp",
        aliases: &["modified"],
        text: |permission| table_time(permission.modified),
    },
];

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn requested(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_string()).collect()
    }

    fn names<T>(columns: &[&Column<T>]) -> Vec<&'static str> {
        columns.iter().map(|column| column.name).collect()
    }

    #[rstest::rstest]
    #[case("first_name", "first_name")]
    #[case("FirstName", "first_name")]
    #[case("firstname", "first_name")]
    #[case("First Name", "first_name")]
    #[case("CreatedTimestamp", "created_timestamp")]
    #[case("createdtimestamp", "created_timestamp")]
    fn test_a_column_is_found_in_every_go_spelling(#[case] column: &str, #[case] expected: &str) {
        assert_eq!(USERS.find(column).unwrap().name, expected);
    }

    #[test]
    fn test_an_unknown_column_is_refused_as_go_refuses_it() {
        let error = GROUPS.find("colour").err().unwrap().to_string();

        assert_eq!(
            error,
            "unknown column: \"colour\" (valid: id, name, created_timestamp, modified_timestamp, \
             deleted, user_count)"
        );
    }

    #[rstest::rstest]
    #[case::resources(names(&RESOURCES.select(&[]).unwrap()), vec!["id", "folder_parent_id", "name", "username", "uri"])]
    #[case::folders(names(&FOLDERS.select(&[]).unwrap()), vec!["id", "folder_parent_id", "name"])]
    #[case::users(names(&USERS.select(&[]).unwrap()), vec!["id", "username", "first_name", "last_name", "role"])]
    #[case::groups(names(&GROUPS.select(&[]).unwrap()), vec!["id", "name"])]
    fn test_the_default_columns_are_go_ones(
        #[case] selected: Vec<&str>,
        #[case] expected: Vec<&str>,
    ) {
        assert_eq!(selected, expected);
    }

    #[test]
    fn test_the_requested_columns_keep_their_order() {
        let selected = RESOURCES.select(&requested(&["Name", "ID"])).unwrap();

        assert_eq!(names(&selected), ["name", "id"]);
    }

    #[rstest::rstest]
    #[case(json!(null), "")]
    #[case(json!(true), "true")]
    #[case(json!({}), "")]
    #[case(json!({"b": 1, "a": "x"}), r#"{"a":"x","b":1}"#)]
    #[case(json!(["https://a.test", "https://b.test"]), "https://a.test, https://b.test")]
    fn test_cells_are_written_as_go_writes_them(#[case] value: Value, #[case] text: &str) {
        assert_eq!(cell(value), text);
    }

    #[test]
    fn test_a_filter_row_reads_flags_as_booleans_and_missing_dates_as_zero() {
        let user: User = serde_json::from_value(json!({
            "id": "u1",
            "username": "ada@passbolt.test",
            "disabled": "2024-01-01T10:00:00+00:00"
        }))
        .unwrap();

        let row = USERS.cel_row(
            crate::util::cel::USER_VARIABLES,
            &["active", "disabled", "created_timestamp"],
            &user,
        );

        assert_eq!(row["active"], CelValue::Bool(false));
        assert_eq!(row["disabled"], CelValue::Bool(true));
        assert_eq!(
            row["created_timestamp"],
            CelValue::Timestamp(zero_timestamp())
        );
    }
}
