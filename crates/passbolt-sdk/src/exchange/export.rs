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

//! Exporting resources as the browser extension does: decrypted, in their folder paths.

use std::collections::HashMap;

use serde_json::Value;

use crate::resource::view::ResourceView;
use crate::types::{CustomField, Folder, TotpData};

use super::csv;
use super::external::{escape_name, ExternalResource};
use super::formats::CsvFormat;

/// The path of each of `folders`, by id: the escaped names from the topmost of `folders`.
#[must_use]
pub fn folder_paths(folders: &[Folder]) -> HashMap<String, String> {
    let by_id: HashMap<&str, &Folder> = folders
        .iter()
        .map(|folder| (folder.id.as_str(), folder))
        .collect();
    folders
        .iter()
        .map(|folder| {
            let mut names = vec![escape_name(&folder.name)];
            let mut parent_id = folder.folder_parent_id.as_deref();
            // A cycle in a broken tree stops at the folders already seen.
            let mut seen = vec![folder.id.as_str()];
            while let Some(parent) = parent_id.and_then(|id| by_id.get(id)) {
                if seen.contains(&parent.id.as_str()) {
                    break;
                }
                seen.push(&parent.id);
                names.push(escape_name(&parent.name));
                parent_id = parent.folder_parent_id.as_deref();
            }
            names.reverse();
            (folder.id.clone(), names.join("/"))
        })
        .collect()
}

/// `views`, their secrets decrypted, as the browser extension exports them.
///
/// The password, else the PIN code; the secret description (the note of v5 types), else the
/// metadata one; the folder path among `folders`, empty outside them.
#[must_use]
pub fn external_resources(views: &[ResourceView], folders: &[Folder]) -> Vec<ExternalResource> {
    let paths = folder_paths(folders);
    views
        .iter()
        .map(|view| {
            let secret = view.secret.clone().unwrap_or_default();
            let text = |key: &str| {
                secret
                    .get(key)
                    .and_then(Value::as_str)
                    .filter(|text| !text.is_empty())
                    .map(String::from)
            };
            ExternalResource {
                name: view.name.clone(),
                username: Some(view.username.clone()).filter(|text| !text.is_empty()),
                uris: view.uris.clone(),
                description: text("description")
                    .or_else(|| Some(view.description.clone()).filter(|text| !text.is_empty())),
                secret_clear: text("password")
                    .or_else(|| text("pin_code"))
                    .unwrap_or_default(),
                folder_parent_path: view
                    .folder_parent_id
                    .as_ref()
                    .and_then(|id| paths.get(id))
                    .cloned()
                    .unwrap_or_default(),
                totp: secret
                    .get("totp")
                    .and_then(|totp| serde_json::from_value::<TotpData>(totp.clone()).ok()),
                expired: view.expired.map(|date| date.to_rfc3339()),
                icon: view.metadata.get("icon").cloned(),
                custom_fields: custom_fields(
                    view.metadata.get("custom_fields"),
                    secret.get("custom_fields"),
                ),
                pin_code: None,
                has_other_values: false,
            }
        })
        .collect()
}

/// The custom fields of the metadata, each with the value its secret side holds.
fn custom_fields(metadata_side: Option<&Value>, secret_side: Option<&Value>) -> Vec<CustomField> {
    let fields = |side: Option<&Value>| -> Vec<CustomField> {
        side.and_then(|value| serde_json::from_value(value.clone()).ok())
            .unwrap_or_default()
    };
    let secrets = fields(secret_side);
    fields(metadata_side)
        .into_iter()
        .map(|mut field| {
            if let Some(secret) = secrets.iter().find(|secret| secret.id == field.id) {
                field.secret_key.clone_from(&secret.secret_key);
                field.secret_value.clone_from(&secret.secret_value);
            }
            field
        })
        .collect()
}

/// `resources` written in `format`.
#[must_use]
pub fn write_csv(format: &CsvFormat, resources: &[ExternalResource]) -> String {
    let rows: Vec<Vec<String>> = resources
        .iter()
        .map(|resource| (format.compose)(format, resource))
        .collect();
    csv::write(&format.columns(), &rows, format.delimiter)
}

/// The name the browser extension gives an export made on `date`:
/// `passbolt-export-2024-01-31.csv`.
#[must_use]
pub fn file_name(date: chrono::NaiveDate, extension: &str) -> String {
    format!("passbolt-export-{}.{extension}", date.format("%Y-%m-%d"))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn folder(id: &str, name: &str, parent: Option<&str>) -> Folder {
        serde_json::from_value(json!({"id": id, "name": name, "folder_parent_id": parent})).unwrap()
    }

    #[test]
    fn test_a_folder_path_starts_at_the_topmost_exported_folder() {
        let folders = [
            folder("1", "Work", Some("outside")),
            folder("2", "a/b", Some("1")),
        ];

        let paths = folder_paths(&folders);

        assert_eq!(paths["1"], "Work");
        assert_eq!(paths["2"], "Work/a / b");
    }

    #[test]
    fn test_a_folder_cycle_does_not_loop() {
        let folders = [folder("1", "A", Some("2")), folder("2", "B", Some("1"))];

        assert_eq!(folder_paths(&folders)["1"], "B/A");
    }

    #[test]
    fn test_the_export_file_is_named_after_the_day() {
        let date = chrono::NaiveDate::from_ymd_opt(2024, 1, 31).unwrap();

        assert_eq!(file_name(date, "csv"), "passbolt-export-2024-01-31.csv");
    }

    #[test]
    fn test_custom_fields_get_their_secret_values() {
        let fields = custom_fields(
            Some(&json!([{"id": "c1", "type": "text", "metadata_key": "Account"}])),
            Some(&json!([{"id": "c1", "type": "text", "secret_value": "42"}])),
        );

        assert_eq!(fields[0].metadata_key.as_deref(), Some("Account"));
        assert_eq!(fields[0].secret_value, Some(json!("42")));
    }
}
