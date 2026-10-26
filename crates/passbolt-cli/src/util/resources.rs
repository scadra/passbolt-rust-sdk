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

//! How resources are shown: list columns and `get resource` rows, for every resource type.

use anyhow::{bail, Result};
use passbolt_sdk::resource::view::ResourceView;
use serde_json::{Map, Value};

/// List columns, by their canonical name.
pub const COLUMNS: [&str; 17] = [
    "id",
    "name",
    "username",
    "uri",
    "uris",
    "description",
    "password",
    "note",
    "folder_parent_id",
    "resource_type",
    "resource_type_id",
    "personal",
    "created",
    "modified",
    "expired",
    "metadata",
    "secret",
];

/// The default list columns.
pub const DEFAULT_COLUMNS: [&str; 5] = ["id", "folder_parent_id", "name", "username", "uri"];

/// The canonical name of `column`, written in any case, with `_`, `-` or spaces,
/// or as go-passbolt-cli names it (`FolderParentID`, `CreatedTimestamp`…).
pub fn column_name(column: &str) -> Result<&'static str> {
    let compact: String = column
        .chars()
        .filter(|character| !matches!(character, '_' | '-' | ' '))
        .collect::<String>()
        .to_lowercase();
    let name = match compact.as_str() {
        "url" => "uri",
        "parent" | "parentid" | "folderparentid" => "folder_parent_id",
        "type" | "resourcetype" => "resource_type",
        "resourcetypeid" => "resource_type_id",
        "createdtimestamp" => "created",
        "modifiedtimestamp" => "modified",
        "expiry" | "expiredat" => "expired",
        other => match COLUMNS.iter().find(|name| name.replace('_', "") == other) {
            Some(name) => name,
            None => bail!("Unknown column {column}. Columns: {}", COLUMNS.join(", ")),
        },
    };
    Ok(name)
}

/// Whether showing `columns` needs the secrets decrypted.
pub fn needs_secrets(columns: &[&str]) -> bool {
    columns
        .iter()
        .any(|column| matches!(*column, "password" | "description" | "note" | "secret"))
}

/// The value of the column `name` (canonical) as JSON.
pub fn column_json(view: &ResourceView, name: &str) -> Result<Value> {
    if name == "note" {
        return Ok(view.note().map_or(Value::Null, Value::from));
    }
    Ok(serde_json::to_value(view)?
        .get(name)
        .cloned()
        .unwrap_or(Value::Null))
}

/// The value of the column `name` (canonical) as table text.
pub fn column_text(view: &ResourceView, name: &str) -> Result<String> {
    Ok(match column_json(view, name)? {
        Value::Null => String::new(),
        Value::String(text) => text,
        Value::Array(items) if name == "uris" => items
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(", "),
        value => value.to_string(),
    })
}

/// `views` as JSON objects with only `columns` (canonical names).
pub fn select_columns(views: &[ResourceView], columns: &[&str]) -> Result<Value> {
    views
        .iter()
        .map(|view| {
            columns
                .iter()
                .map(|name| Ok(((*name).to_string(), column_json(view, name)?)))
                .collect::<Result<Map<String, Value>>>()
                .map(Value::Object)
        })
        .collect()
}

/// `key=value` arguments as fields; a value that is JSON is read as JSON, otherwise as text.
pub fn parse_fields(arguments: &[String]) -> Result<Map<String, Value>> {
    arguments
        .iter()
        .map(|argument| {
            let Some((key, value)) = argument.split_once('=') else {
                bail!("Expected key=value, got {argument}");
            };
            let value = serde_json::from_str(value).unwrap_or_else(|_| Value::from(value));
            Ok((key.to_string(), value))
        })
        .collect()
}

/// The rows of `get resource`: the common fields, then what the type holds.
pub fn detail_rows(view: &ResourceView) -> Vec<(String, String)> {
    let mut rows = vec![
        ("ID".to_string(), view.id.clone()),
        (
            "Type".into(),
            view.resource_type.clone().unwrap_or_default(),
        ),
        ("Name".into(), view.name.clone()),
        ("Username".into(), view.username.clone()),
        ("URI".into(), view.uris.join(", ")),
        ("Password".into(), view.password.clone().unwrap_or_default()),
        ("Description".into(), view.description.clone()),
    ];
    let secret = view.secret.clone().unwrap_or_default();
    if let Some(note) = view.note() {
        rows.push(("Note".into(), note.to_string()));
    }
    if let Some(pin_code) = secret.get("pin_code").and_then(Value::as_str) {
        rows.push(("PIN code".into(), pin_code.to_string()));
    }
    if let Some(totp) = secret.get("totp") {
        let field = |key: &str| {
            totp.get(key)
                .map(|value| {
                    value
                        .as_str()
                        .map_or_else(|| value.to_string(), String::from)
                })
                .unwrap_or_default()
        };
        rows.push((
            "TOTP".into(),
            format!(
                "{} ({}, {} digits, {} s)",
                field("secret_key"),
                field("algorithm"),
                field("digits"),
                field("period")
            ),
        ));
    }
    for (key, value) in custom_fields(
        view.metadata.get("custom_fields"),
        secret.get("custom_fields"),
    ) {
        rows.push((key, value));
    }
    if let Some(icon) = view.metadata.get("icon") {
        rows.push(("Icon".into(), icon.to_string()));
    }
    rows.push((
        "Expiry".into(),
        view.expired
            .map(|date| date.to_rfc3339())
            .unwrap_or_default(),
    ));
    rows
}

/// Custom fields as `(key, value)`, their metadata and secret sides paired by id.
pub fn custom_fields(
    metadata_side: Option<&Value>,
    secret_side: Option<&Value>,
) -> Vec<(String, String)> {
    let as_list =
        |side: Option<&Value>| side.and_then(Value::as_array).cloned().unwrap_or_default();
    let secret_fields = as_list(secret_side);
    let text = |value: Option<&Value>| match value {
        Some(Value::String(text)) => Some(text.clone()),
        Some(Value::Null) | None => None,
        Some(value) => Some(value.to_string()),
    };
    as_list(metadata_side)
        .iter()
        .map(|field| {
            let secret = secret_fields
                .iter()
                .find(|secret| secret["id"] == field["id"]);
            let key = text(field.get("metadata_key"))
                .or_else(|| text(secret.and_then(|secret| secret.get("secret_key"))))
                .unwrap_or_default();
            let value = text(secret.and_then(|secret| secret.get("secret_value")))
                .or_else(|| text(field.get("metadata_value")))
                .unwrap_or_default();
            (key, value)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[rstest::rstest]
    #[case("ID", "id")]
    #[case("FolderParentID", "folder_parent_id")]
    #[case("folder-parent-id", "folder_parent_id")]
    #[case("CreatedTimestamp", "created")]
    #[case("URL", "uri")]
    #[case("Type", "resource_type")]
    #[case("resource_type_id", "resource_type_id")]
    #[case("Secret", "secret")]
    fn test_column_name_accepts_every_spelling(#[case] column: &str, #[case] expected: &str) {
        assert_eq!(column_name(column).unwrap(), expected);
    }

    #[test]
    fn test_column_name_rejects_an_unknown_column() {
        let error = column_name("colour").unwrap_err().to_string();

        assert!(error.contains("Unknown column colour"), "{error}");
    }

    #[test]
    fn test_parse_fields_reads_json_values() {
        let fields = parse_fields(&[
            "name=GitHub".into(),
            "uris=[\"https://a.test\"]".into(),
            "count=3".into(),
        ])
        .unwrap();

        assert_eq!(
            Value::Object(fields),
            json!({"name": "GitHub", "uris": ["https://a.test"], "count": 3})
        );
    }

    #[test]
    fn test_parse_fields_needs_an_equal_sign() {
        assert!(parse_fields(&["name".into()]).is_err());
    }

    #[test]
    fn test_custom_fields_pair_both_sides_by_id() {
        let metadata = json!([{"id": "c1", "type": "text", "metadata_key": "Account"}]);
        let secret = json!([{"id": "c1", "type": "text", "secret_value": "42"}]);

        assert_eq!(
            custom_fields(Some(&metadata), Some(&secret)),
            [("Account".to_string(), "42".to_string())]
        );
    }
}
