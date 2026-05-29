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

//! Reading a KDBX file as the browser extension reads it: every group becomes a folder, the
//! root group included, every entry a resource.

use anyhow::{Context, Result};
use keepass::db::{Entry, Group, Node, Value};
use keepass::{Database, DatabaseKey};
use passbolt_sdk::error::PassboltError;
use passbolt_sdk::exchange::external::{
    child_path, escape_name, leading_number, parse_totp_uri, text_custom_field,
    totp_with_defaults, ExternalResource,
};
use passbolt_sdk::exchange::import::ImportIssue;
use passbolt_sdk::types::TotpData;

/// The fields read into the resource; the others become custom fields.
const SUPPORTED_FIELDS: [&str; 10] = [
    "Title",
    "URL",
    "UserName",
    "Notes",
    "otp",
    "TimeOtp-Secret-Base32",
    "TimeOtp-Algorithm",
    "TimeOtp-Length",
    "TimeOtp-Period",
    "Password",
];
const ADDITIONAL_URL_PREFIX: &str = "KP2A_URL";
const MAX_ADDITIONAL_URIS: usize = 31;

/// The entries and groups of a KDBX file.
pub struct KdbxContent {
    pub resources: Vec<Result<ExternalResource, (String, PassboltError)>>,
    /// The path of every group, parents first.
    pub folders: Vec<String>,
    pub warnings: Vec<ImportIssue>,
}

/// Open `file` with its password and key file, either one being optional.
pub fn open(file: &[u8], password: Option<&str>, keyfile: Option<&[u8]>) -> Result<Database> {
    let mut key = DatabaseKey::new();
    if let Some(password) = password {
        key = key.with_password(password);
    }
    if let Some(mut keyfile) = keyfile {
        key = key.with_keyfile(&mut keyfile)?;
    }
    Database::open(&mut &file[..], key).context("Cannot open the KDBX file")
}

/// The resources and folders of `database`; custom fields and icons only for v5 resources.
pub fn read(database: &Database, v5: bool) -> KdbxContent {
    let mut content = KdbxContent {
        resources: Vec::new(),
        folders: Vec::new(),
        warnings: Vec::new(),
    };
    read_group(&database.root, "", v5, &mut content);
    content
}

fn read_group(group: &Group, parent_path: &str, v5: bool, content: &mut KdbxContent) {
    let path = child_path(parent_path, &escape_name(&group.name));
    content.folders.push(path.clone());
    let (groups, entries): (Vec<_>, Vec<_>) = group
        .children
        .iter()
        .partition(|node| matches!(node, Node::Group(_)));
    for node in groups {
        if let Node::Group(child) = node {
            read_group(child, &path, v5, content);
        }
    }
    for node in entries {
        if let Node::Entry(entry) = node {
            let resource = read_entry(entry, &path, v5, &mut content.warnings);
            content.resources.push(resource);
        }
    }
}

fn read_entry(
    entry: &Entry,
    folder_parent_path: &str,
    v5: bool,
    warnings: &mut Vec<ImportIssue>,
) -> Result<ExternalResource, (String, PassboltError)> {
    let text = |key: &str| {
        entry
            .get(key)
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(str::to_string)
    };
    let name = text("Title").unwrap_or_default();
    let mut resource = ExternalResource {
        username: text("UserName"),
        description: text("Notes"),
        folder_parent_path: folder_parent_path.to_string(),
        // An unprotected password is not read, as the browser extension does.
        secret_clear: protected(entry, "Password").unwrap_or_default(),
        expired: entry
            .times
            .expires
            .then(|| entry.times.get_expiry())
            .flatten()
            .map(|expiry| expiry.and_utc().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()),
        uris: uris(entry, &name, warnings),
        totp: totp(entry).map_err(|error| (name.clone(), error))?,
        ..ExternalResource::default()
    };
    if v5 {
        resource.custom_fields = custom_fields(entry);
        resource.icon = icon(entry);
    }
    resource.name = name;
    Ok(resource)
}

/// The text of a protected field.
fn protected(entry: &Entry, key: &str) -> Option<String> {
    match entry.fields.get(key) {
        Some(Value::Protected(_)) => entry.get(key).map(str::to_string),
        _ => None,
    }
}

/// The URL then the `KP2A_URL` fields, 32 at most.
fn uris(entry: &Entry, name: &str, warnings: &mut Vec<ImportIssue>) -> Vec<String> {
    let mut keys: Vec<&String> = entry
        .fields
        .keys()
        .filter(|key| key.starts_with(ADDITIONAL_URL_PREFIX))
        .collect();
    // KP2A_URL, KP2A_URL_1, KP2A_URL_2, … KP2A_URL_10, in the order they were added.
    keys.sort_by_key(|key| (key.len(), *key));
    if keys.len() > MAX_ADDITIONAL_URIS {
        warnings.push(ImportIssue {
            title: "Resource has more than 32 URIs, only the first 32 will be imported".into(),
            detail: String::new(),
            item: name.to_string(),
        });
    }
    let url = entry.get("URL").map(str::trim).unwrap_or_default();
    std::iter::once(url)
        .chain(
            keys.into_iter()
                .take(MAX_ADDITIONAL_URIS)
                .map(|key| entry.get(key).map(str::trim).unwrap_or_default()),
        )
        .map(str::to_string)
        .collect()
}

/// The `otp` URI of `KeePassXC`, else the `TimeOtp-*` fields of `KeePass`.
fn totp(entry: &Entry) -> Result<Option<TotpData>, PassboltError> {
    if let Some(uri) = entry.get("otp").filter(|uri| !uri.is_empty()) {
        return parse_totp_uri(uri).map(Some);
    }
    let Some(secret_key) = protected(entry, "TimeOtp-Secret-Base32") else {
        return Ok(None);
    };
    let unprotected = |key: &str| match entry.fields.get(key) {
        Some(Value::Unprotected(text)) => Some(text.as_str()),
        _ => None,
    };
    // HMAC-SHA-256 → SHA256
    let algorithm = unprotected("TimeOtp-Algorithm")
        .and_then(|algorithm| algorithm.get(5..))
        .map(|algorithm| algorithm.replacen('-', "", 1));
    Ok(Some(totp_with_defaults(
        secret_key,
        algorithm,
        unprotected("TimeOtp-Length").and_then(leading_number),
        unprotected("TimeOtp-Period").and_then(leading_number),
    )))
}

/// Every other text field, sorted by name.
fn custom_fields(entry: &Entry) -> Vec<passbolt_sdk::types::CustomField> {
    let mut keys: Vec<&String> = entry
        .fields
        .keys()
        .filter(|key| {
            !SUPPORTED_FIELDS.contains(&key.as_str()) && !key.starts_with(ADDITIONAL_URL_PREFIX)
        })
        .collect();
    keys.sort();
    keys.into_iter()
        .filter_map(|key| {
            let value = entry.get(key)?;
            Some(text_custom_field(key.clone(), value.to_string()))
        })
        .collect()
}

/// Its `KeePass` icon and background colour, when it has one besides the default key icon.
fn icon(entry: &Entry) -> Option<serde_json::Value> {
    let icon_id = entry.icon_id.filter(|icon_id| *icon_id != 0);
    let color = entry
        .background_color
        .as_ref()
        .map(|color| format!("#{:02X}{:02X}{:02X}", color.r, color.g, color.b));
    if icon_id.is_none() && color.is_none() {
        return None;
    }
    let mut icon = serde_json::Map::new();
    if let Some(icon_id) = icon_id {
        icon.insert("type".into(), "keepass-icon-set".into());
        icon.insert("value".into(), icon_id.into());
    }
    if let Some(color) = color {
        icon.insert("background_color".into(), color.into());
    }
    Some(serde_json::Value::Object(icon))
}
