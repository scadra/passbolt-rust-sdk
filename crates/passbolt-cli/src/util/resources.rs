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

//! How resources are written and shown: `--field` values and `get resource` lines.

use anyhow::{bail, Result};
use passbolt_sdk::resource::view::ResourceView;
use serde_json::{Map, Value};

use crate::util::shapes::{self, go_sprint, metadata_text};

/// `key=value` arguments as fields, as go-passbolt-cli reads them: a value starting with `[` or
/// `{` that is JSON is read as JSON, any other value as text.
pub fn parse_fields(arguments: &[String]) -> Result<Map<String, Value>> {
    arguments
        .iter()
        .map(|argument| {
            let Some((key, value)) = argument.split_once('=') else {
                bail!("expected key=value, got {argument:?}");
            };
            let trimmed = value.trim();
            let json = (trimmed.starts_with('[') || trimmed.starts_with('{'))
                .then(|| serde_json::from_str(trimmed).ok())
                .flatten();
            Ok((key.to_string(), json.unwrap_or_else(|| Value::from(value))))
        })
        .collect()
}

/// The lines of `get resource`: go-passbolt-cli's, then its other metadata fields, then what
/// only the secret holds.
pub fn detail_rows(view: &ResourceView) -> Vec<(String, String)> {
    let metadata = shapes::resource_metadata(view);
    let mut rows = vec![
        (
            "FolderParentID".to_string(),
            view.folder_parent_id.clone().unwrap_or_default(),
        ),
        ("Name".into(), metadata_text(&metadata, "name")),
        ("Username".into(), metadata_text(&metadata, "username")),
        ("URI".into(), metadata_text(&metadata, "uri")),
        ("Password".into(), view.password.clone().unwrap_or_default()),
        (
            "Description".into(),
            metadata_text(&metadata, "description"),
        ),
    ];
    for (key, value) in &metadata {
        if !matches!(
            key.as_str(),
            "name"
                | "username"
                | "uri"
                | "uris"
                | "description"
                | "object_type"
                | "resource_type_id"
        ) {
            rows.push((key.clone(), go_sprint(value)));
        }
    }
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
    for (key, value) in custom_fields(metadata.get("custom_fields"), secret.get("custom_fields")) {
        rows.push((key, value));
    }
    if let Some(expired) = view.expired {
        rows.push(("Expiry".into(), shapes::table_time(Some(expired))));
    }
    rows
}

/// Custom fields as `(key, value)`, their metadata and secret sides paired by id.
fn custom_fields(
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

    #[test]
    fn test_parse_fields_reads_only_lists_and_objects_as_json() {
        let fields = parse_fields(&[
            "name=GitHub".into(),
            "uris=[\"https://a.test\"]".into(),
            "icon= {\"value\": 42}".into(),
            "count=3".into(),
            "flag=true".into(),
            "quoted=\"q\"".into(),
            "broken=[x".into(),
        ])
        .unwrap();

        assert_eq!(
            Value::Object(fields),
            json!({
                "name": "GitHub",
                "uris": ["https://a.test"],
                "icon": {"value": 42},
                "count": "3",
                "flag": "true",
                "quoted": "\"q\"",
                "broken": "[x"
            })
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
