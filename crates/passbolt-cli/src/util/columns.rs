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

//! Columns of `list folder`, `list user`, `list group` and of the permissions, named as
//! go-passbolt-cli names them.

use anyhow::{bail, Result};
use passbolt_sdk::types::{Folder, Group, GroupUser, Permission, User};
use serde_json::{Map, Value};

use crate::util::output;

/// A list column: its canonical name, other accepted spellings, its table header and value.
pub struct Column<T> {
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    pub header: &'static str,
    pub value: fn(&T) -> Value,
}

/// Lower case, without `_`, `-` or spaces: `First Name`, `first_name` and `FirstName` match.
fn compact(name: &str) -> String {
    name.chars()
        .filter(|character| !matches!(character, '_' | '-' | ' '))
        .collect::<String>()
        .to_lowercase()
}

/// The columns named by `requested`, or `defaults` when none is; an unknown name is an error.
pub fn resolve<'a, T>(
    columns: &'a [Column<T>],
    requested: &[String],
    defaults: &[&str],
) -> Result<Vec<&'a Column<T>>> {
    let names: Vec<&str> = if requested.is_empty() {
        defaults.to_vec()
    } else {
        requested.iter().map(String::as_str).collect()
    };
    names
        .into_iter()
        .map(|name| {
            let wanted = compact(name);
            columns
                .iter()
                .find(|column| {
                    compact(column.name) == wanted
                        || column.aliases.iter().any(|alias| compact(alias) == wanted)
                })
                .map_or_else(
                    || {
                        let known: Vec<&str> = columns.iter().map(|column| column.name).collect();
                        bail!("Unknown column {name}. Columns: {}", known.join(", "))
                    },
                    Ok,
                )
        })
        .collect()
}

/// Print `items` as a table of `columns`, or as JSON: full objects without requested columns.
pub fn print<T: serde::Serialize>(
    items: &[T],
    columns: &[Column<T>],
    requested: &[String],
    defaults: &[&str],
    json: bool,
) -> Result<()> {
    let selected = resolve(columns, requested, defaults)?;
    if json {
        if requested.is_empty() {
            return output::print_json(&items);
        }
        let objects: Vec<Value> = items
            .iter()
            .map(|item| {
                Value::Object(
                    selected
                        .iter()
                        .map(|column| (column.name.to_string(), (column.value)(item)))
                        .collect::<Map<String, Value>>(),
                )
            })
            .collect();
        return output::print_json(&objects);
    }
    let headers: Vec<&str> = selected.iter().map(|column| column.header).collect();
    let rows = items
        .iter()
        .map(|item| {
            selected
                .iter()
                .map(|column| text((column.value)(item)))
                .collect()
        })
        .collect();
    output::print_table(&headers, rows);
    Ok(())
}

fn text(value: Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(text) => text,
        value => value.to_string(),
    }
}

fn date(date: Option<chrono::DateTime<chrono::Utc>>) -> Value {
    date.map_or(Value::Null, |date| date.to_rfc3339().into())
}

pub const FOLDER_DEFAULTS: [&str; 3] = ["id", "name", "folder_parent_id"];
pub const FOLDER_COLUMNS: [Column<Folder>; 6] = [
    Column {
        name: "id",
        aliases: &[],
        header: "ID",
        value: |folder| folder.id.clone().into(),
    },
    Column {
        name: "name",
        aliases: &[],
        header: "Name",
        value: |folder| folder.name.clone().into(),
    },
    Column {
        name: "folder_parent_id",
        aliases: &["parent", "parent id"],
        header: "Parent ID",
        value: |folder| folder.folder_parent_id.clone().into(),
    },
    Column {
        name: "created",
        aliases: &["created_timestamp"],
        header: "Created",
        value: |folder| date(folder.created),
    },
    Column {
        name: "modified",
        aliases: &["modified_timestamp"],
        header: "Modified",
        value: |folder| date(folder.modified),
    },
    Column {
        name: "personal",
        aliases: &[],
        header: "Personal",
        value: |folder| folder.personal.into(),
    },
];

pub const USER_DEFAULTS: [&str; 5] = ["id", "username", "first_name", "last_name", "role"];
pub const USER_COLUMNS: [Column<User>; 8] = [
    Column {
        name: "id",
        aliases: &[],
        header: "ID",
        value: |user| user.id.clone().into(),
    },
    Column {
        name: "username",
        aliases: &[],
        header: "Username",
        value: |user| user.username.clone().into(),
    },
    Column {
        name: "first_name",
        aliases: &[],
        header: "First Name",
        value: |user| user.first_name().into(),
    },
    Column {
        name: "last_name",
        aliases: &[],
        header: "Last Name",
        value: |user| user.last_name().into(),
    },
    Column {
        name: "role",
        aliases: &[],
        header: "Role",
        value: |user| user.role_name().into(),
    },
    Column {
        name: "active",
        aliases: &[],
        header: "Active",
        value: |user| user.active.into(),
    },
    Column {
        name: "created",
        aliases: &["created_timestamp"],
        header: "Created",
        value: |user| date(user.created),
    },
    Column {
        name: "modified",
        aliases: &["modified_timestamp"],
        header: "Modified",
        value: |user| date(user.modified),
    },
];

pub const GROUP_DEFAULTS: [&str; 3] = ["id", "name", "members"];
pub const GROUP_COLUMNS: [Column<Group>; 5] = [
    Column {
        name: "id",
        aliases: &[],
        header: "ID",
        value: |group| group.id.clone().into(),
    },
    Column {
        name: "name",
        aliases: &[],
        header: "Name",
        value: |group| group.name.clone().into(),
    },
    Column {
        name: "members",
        aliases: &["user_count"],
        header: "Members",
        value: |group| group.groups_users.len().into(),
    },
    Column {
        name: "created",
        aliases: &["created_timestamp"],
        header: "Created",
        value: |group| date(group.created),
    },
    Column {
        name: "modified",
        aliases: &["modified_timestamp"],
        header: "Modified",
        value: |group| date(group.modified),
    },
];

/// Members of `get group`, as go-passbolt-cli shows them.
pub const GROUP_MEMBER_DEFAULTS: [&str; 5] = [
    "user_id",
    "username",
    "first_name",
    "last_name",
    "is_group_manager",
];
pub const GROUP_MEMBER_COLUMNS: [Column<GroupUser>; 5] = [
    Column {
        name: "user_id",
        aliases: &[],
        header: "User ID",
        value: |member| member.user_id.clone().into(),
    },
    Column {
        name: "username",
        aliases: &[],
        header: "Username",
        value: |member| {
            member
                .user
                .as_ref()
                .and_then(|user| user.username.clone())
                .into()
        },
    },
    Column {
        name: "first_name",
        aliases: &["user_first_name"],
        header: "First Name",
        value: |member| {
            member
                .user
                .as_ref()
                .map(|user| user.first_name().to_string())
                .into()
        },
    },
    Column {
        name: "last_name",
        aliases: &["user_last_name"],
        header: "Last Name",
        value: |member| {
            member
                .user
                .as_ref()
                .map(|user| user.last_name().to_string())
                .into()
        },
    },
    Column {
        name: "is_group_manager",
        aliases: &["manager", "role"],
        header: "Manager",
        value: |member| member.is_admin.unwrap_or(false).into(),
    },
];

/// `get resource-permissions` and `get folder-permissions`.
pub const PERMISSION_COLUMNS: [Column<Permission>; 5] = [
    Column {
        name: "aro",
        aliases: &[],
        header: "ARO",
        value: |permission| permission.aro.clone().into(),
    },
    Column {
        name: "aro_foreign_key",
        aliases: &["aro_id"],
        header: "ARO ID",
        value: |permission| permission.aro_foreign_key.clone().into(),
    },
    Column {
        name: "type",
        aliases: &["permission_type"],
        header: "Type",
        value: |permission| permission.type_name().into(),
    },
    Column {
        name: "id",
        aliases: &[],
        header: "ID",
        value: |permission| permission.id.clone().into(),
    },
    Column {
        name: "modified",
        aliases: &[],
        header: "Modified",
        value: |permission| {
            permission
                .modified
                .map(|modified| modified.to_rfc3339())
                .into()
        },
    },
];

pub const PERMISSION_DEFAULTS: [&str; 3] = ["aro", "aro_foreign_key", "type"];

#[cfg(test)]
mod tests {
    use super::*;

    fn requested(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_string()).collect()
    }

    #[rstest::rstest]
    #[case("First Name", "first_name")]
    #[case("FirstName", "first_name")]
    #[case("last-name", "last_name")]
    #[case("CreatedTimestamp", "created")]
    fn test_resolve_accepts_go_passbolt_cli_spellings(
        #[case] column: &str,
        #[case] expected: &str,
    ) {
        let selected = resolve(&USER_COLUMNS, &requested(&[column]), &USER_DEFAULTS).unwrap();

        assert_eq!(selected[0].name, expected);
    }

    #[test]
    fn test_resolve_refuses_an_unknown_column() {
        let error = resolve(&GROUP_COLUMNS, &requested(&["colour"]), &GROUP_DEFAULTS)
            .err()
            .unwrap()
            .to_string();

        assert!(error.contains("Unknown column colour"), "{error}");
    }

    #[test]
    fn test_resolve_uses_the_defaults_without_columns() {
        let selected = resolve(&FOLDER_COLUMNS, &[], &FOLDER_DEFAULTS).unwrap();

        let names: Vec<&str> = selected.iter().map(|column| column.name).collect();
        assert_eq!(names, FOLDER_DEFAULTS);
    }

    #[test]
    fn test_group_members_accept_go_passbolt_cli_names() {
        let names: Vec<&str> = resolve(
            &GROUP_MEMBER_COLUMNS,
            &requested(&[
                "UserID",
                "Username",
                "UserFirstName",
                "UserLastName",
                "IsGroupManager",
            ]),
            &GROUP_MEMBER_DEFAULTS,
        )
        .unwrap()
        .iter()
        .map(|column| column.name)
        .collect();

        assert_eq!(names, GROUP_MEMBER_DEFAULTS);
    }

    #[test]
    fn test_user_names_come_from_the_profile() {
        let user: User = serde_json::from_value(serde_json::json!({
            "id": "u1",
            "username": "ada@passbolt.test",
            "profile": {"first_name": "Ada", "last_name": "Lovelace"}
        }))
        .unwrap();

        assert_eq!((USER_COLUMNS[2].value)(&user), "Ada");
        assert_eq!((USER_COLUMNS[3].value)(&user), "Lovelace");
    }
}
