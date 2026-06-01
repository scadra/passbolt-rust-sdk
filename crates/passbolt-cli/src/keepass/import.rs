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

use passbolt_sdk::error::PassboltError;
use passbolt_sdk::exchange::external::{
    child_path, escape_name, leading_number, parse_totp_uri, text_custom_field, totp_with_defaults,
    ExternalResource,
};
use passbolt_sdk::exchange::import::ImportIssue;
use passbolt_sdk::types::{CustomField, TotpData};

use super::kdbx::{Entry, Group};

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

/// The resources and folders below `root`; custom fields and icons only for v5 resources.
#[must_use]
pub fn read(root: &Group, v5: bool) -> KdbxContent {
    let mut content = KdbxContent {
        resources: Vec::new(),
        folders: Vec::new(),
        warnings: Vec::new(),
    };
    read_group(root, "", v5, &mut content);
    content
}

/// The group, then its groups, then its entries.
fn read_group(group: &Group, parent_path: &str, v5: bool, content: &mut KdbxContent) {
    let path = child_path(parent_path, &escape_name(&group.name));
    content.folders.push(path.clone());
    for child in &group.groups {
        read_group(child, &path, v5, content);
    }
    for entry in &group.entries {
        let resource = read_entry(entry, &path, v5, &mut content.warnings);
        content.resources.push(resource);
    }
}

fn read_entry(
    entry: &Entry,
    folder_parent_path: &str,
    v5: bool,
    warnings: &mut Vec<ImportIssue>,
) -> Result<ExternalResource, (String, PassboltError)> {
    let name = text(entry, "Title").unwrap_or_default();
    let mut resource = ExternalResource {
        username: text(entry, "UserName"),
        description: text(entry, "Notes"),
        folder_parent_path: folder_parent_path.to_string(),
        // An unprotected password is not read, as the browser extension does.
        secret_clear: protected(entry, "Password").unwrap_or_default(),
        expired: entry
            .expires
            .then_some(entry.expiry_time)
            .flatten()
            .map(|expiry| {
                expiry
                    .and_utc()
                    .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                    .to_string()
            }),
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

/// The trimmed text of a field, when not empty.
fn text(entry: &Entry, key: &str) -> Option<String> {
    entry
        .field(key)
        .map(|field| field.value.trim())
        .filter(|text| !text.is_empty())
        .map(str::to_string)
}

/// The text of a protected field.
fn protected(entry: &Entry, key: &str) -> Option<String> {
    entry
        .field(key)
        .filter(|field| field.protected)
        .map(|field| field.value.to_string())
}

/// The text of an unprotected field.
fn unprotected<'a>(entry: &'a Entry, key: &str) -> Option<&'a str> {
    entry
        .field(key)
        .filter(|field| !field.protected)
        .map(|field| field.value.as_str())
}

/// The URL then the `KP2A_URL` fields, 32 at most.
fn uris(entry: &Entry, name: &str, warnings: &mut Vec<ImportIssue>) -> Vec<String> {
    let additional: Vec<&str> = entry
        .fields
        .iter()
        .filter(|field| field.key.starts_with(ADDITIONAL_URL_PREFIX))
        .map(|field| field.value.trim())
        .collect();
    if additional.len() > MAX_ADDITIONAL_URIS {
        warnings.push(ImportIssue {
            title: "Resource has more than 32 URIs, only the first 32 will be imported".into(),
            detail: String::new(),
            item: name.to_string(),
        });
    }
    std::iter::once(text(entry, "URL").unwrap_or_default())
        .chain(
            additional
                .into_iter()
                .take(MAX_ADDITIONAL_URIS)
                .map(str::to_string),
        )
        .collect()
}

/// The `otp` URI of `KeePassXC`, else the `TimeOtp-*` fields of `KeePass`.
fn totp(entry: &Entry) -> Result<Option<TotpData>, PassboltError> {
    if let Some(uri) = entry.field("otp").filter(|uri| !uri.value.is_empty()) {
        return parse_totp_uri(&uri.value).map(Some);
    }
    let Some(secret_key) = protected(entry, "TimeOtp-Secret-Base32") else {
        return Ok(None);
    };
    // HMAC-SHA-256 → SHA256
    let algorithm = unprotected(entry, "TimeOtp-Algorithm")
        .and_then(|algorithm| algorithm.get(5..))
        .map(|algorithm| algorithm.replacen('-', "", 1));
    Ok(Some(totp_with_defaults(
        &secret_key,
        algorithm,
        unprotected(entry, "TimeOtp-Length").and_then(leading_number),
        unprotected(entry, "TimeOtp-Period").and_then(leading_number),
    )))
}

/// Every other field, as a text custom field.
fn custom_fields(entry: &Entry) -> Vec<CustomField> {
    entry
        .fields
        .iter()
        .filter(|field| {
            !SUPPORTED_FIELDS.contains(&field.key.as_str())
                && !field.key.starts_with(ADDITIONAL_URL_PREFIX)
        })
        .map(|field| text_custom_field(field.key.clone(), field.value.to_string()))
        .collect()
}

/// Its `KeePass` icon and background colour, when it has one besides the default key icon.
fn icon(entry: &Entry) -> Option<serde_json::Value> {
    let icon_id = entry.icon_id.filter(|icon_id| *icon_id != 0);
    if icon_id.is_none() && entry.background_color.is_none() {
        return None;
    }
    let mut icon = serde_json::Map::new();
    if let Some(icon_id) = icon_id {
        icon.insert("type".into(), "keepass-icon-set".into());
        icon.insert("value".into(), icon_id.into());
    }
    if let Some(color) = &entry.background_color {
        icon.insert("background_color".into(), color.clone().into());
    }
    Some(serde_json::Value::Object(icon))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keepass::kdbx;
    use rstest::rstest;

    const KEYFILE: &[u8] = include_bytes!("../../tests/fixtures/kdbx/kdbx-keyfile.key");

    /// The browser extension's test file `name`, opened.
    fn open(name: &str, password: Option<&str>, keyfile: Option<&[u8]>) -> kdbx::Group {
        let path = format!("{}/tests/fixtures/kdbx/{name}", env!("CARGO_MANIFEST_DIR"));
        kdbx::read(&std::fs::read(path).unwrap(), password, keyfile).unwrap()
    }

    fn read_file(name: &str, password: Option<&str>, v5: bool) -> KdbxContent {
        read(&open(name, password, None), v5)
    }

    fn resources(content: &KdbxContent) -> Vec<&ExternalResource> {
        content
            .resources
            .iter()
            .map(|resource| resource.as_ref().unwrap())
            .collect()
    }

    #[test]
    fn test_groups_become_folders_and_entries_resources_groups_first() {
        let content = read_file("kdbx-not-protected.kdbx", None, false);

        let paths: Vec<(&str, &str)> = resources(&content)
            .iter()
            .map(|resource| (resource.name.as_str(), resource.folder_parent_path.as_str()))
            .collect();
        assert_eq!(
            paths,
            [
                ("Password 1", "Root/Folder 1/Folder 2"),
                ("Password 2", "Root/Folder 1"),
                ("Password 4", "Root/Folder 2/Folder 1"),
                ("Password 3", "Root/Folder 3/Folder 4"),
            ]
        );
        assert_eq!(content.folders.len(), 8);
        assert_eq!(content.folders[0], "Root");
        assert!(content.folders.contains(&"Root/Folder 5".to_string()));
    }

    #[test]
    fn test_an_entry_keeps_its_fields() {
        let content = read_file("kdbx-not-protected.kdbx", None, false);

        let resource = resources(&content)[1];
        assert_eq!(resource.username.as_deref(), Some("username2"));
        assert_eq!(resource.uris, ["https://url2.com"]);
        assert_eq!(resource.description.as_deref(), Some("Description 2"));
        assert_eq!(resource.secret_clear, "Secret 2");
        assert_eq!(resource.expired, None);
    }

    #[test]
    fn test_a_file_opens_with_its_key_file() {
        let root = open("kdbx-protected-keyfile.kdbx", None, Some(KEYFILE));

        assert_eq!(root.name, "Root");
    }

    #[rstest]
    #[case::wrong_password("kdbx-protected-password.kdbx", Some("wrong"), None)]
    #[case::no_password("kdbx-protected-password.kdbx", None, None)]
    #[case::wrong_key_file("kdbx-protected-password.kdbx", Some("passbolt"), Some(KEYFILE))]
    #[case::missing_key_file("kdbx-protected-keyfile.kdbx", None, None)]
    fn test_wrong_credentials_are_refused(
        #[case] name: &str,
        #[case] password: Option<&str>,
        #[case] keyfile: Option<&[u8]>,
    ) {
        let path = format!("{}/tests/fixtures/kdbx/{name}", env!("CARGO_MANIFEST_DIR"));

        let error = kdbx::read(&std::fs::read(path).unwrap(), password, keyfile).unwrap_err();

        assert_eq!(
            error.to_string(),
            "Cannot open the KDBX file: wrong password or key file"
        );
    }

    #[rstest]
    #[case::kdbx3("kdbx-protected-password.kdbx", 1, Some("2020-11-16T23:00:42.000Z"))]
    #[case::kdbx4("kdbx-expiry.kdbx", 0, Some("2025-12-09T12:41:34.000Z"))]
    #[case::never("kdbx-never-expiry.kdbx", 0, None)]
    fn test_the_expiry_date_is_read(
        #[case] name: &str,
        #[case] index: usize,
        #[case] expired: Option<&str>,
    ) {
        let content = read_file(name, Some("passbolt"), false);

        assert_eq!(resources(&content)[index].expired.as_deref(), expired);
    }

    #[rstest]
    #[case::otp_uri(
        "kdbx-with-totp-protected-password.kdbx",
        "Password 1",
        totp_with_defaults("TJSNMLGTCYOEMXZG", None, None, None)
    )]
    #[case::keepass_fields_with_defaults(
        "kdbx-windows-with-totp-protected-password.kdbx",
        "Password 2",
        totp_with_defaults("THISISANOTHERSECRET", None, None, None)
    )]
    #[case::keepass_fields(
        "kdbx-windows-with-totp-protected-password.kdbx",
        "Password 3",
        totp_with_defaults("THISISTOTPSECRT", Some("SHA256".into()), Some(8), Some(60))
    )]
    fn test_the_totp_is_read(#[case] file: &str, #[case] name: &str, #[case] totp: TotpData) {
        let content = read_file(file, Some("passbolt"), false);

        let resource = resources(&content)
            .into_iter()
            .find(|resource| resource.name == name)
            .unwrap();
        assert_eq!(resource.totp, Some(totp));
    }

    #[test]
    fn test_the_icon_and_background_color_are_read_for_v5() {
        let content = read_file(
            "kdbx-protected-with-color-and-icon.kdbx",
            Some("passbolt"),
            true,
        );

        let resources = resources(&content);
        assert_eq!(
            resources[0].icon,
            Some(serde_json::json!({
                "type": "keepass-icon-set",
                "value": 4,
                "background_color": "#FF0000",
            }))
        );
        assert_eq!(resources[1].icon, None);
    }

    #[test]
    fn test_additional_urls_follow_the_url() {
        let content = read_file("kdbx-multiple-uris.kdbx", Some("passbolt"), true);

        assert_eq!(
            resources(&content)[0].uris,
            [
                "https://main.url",
                "https://additional1.url",
                "https://additional2.url",
                "https://additional3.url",
            ]
        );
    }

    #[test]
    fn test_only_32_urls_are_read_with_a_warning() {
        let content = read_file(
            "kdbx-multiple-uris-with-33-entries.kdbx",
            Some("passbolt"),
            true,
        );

        assert_eq!(resources(&content)[0].uris.len(), 32);
        assert_eq!(content.warnings.len(), 1);
    }

    #[rstest]
    #[case::text_fields("kdbx-custom-fields-with-uris.kdbx", 3, 3)]
    #[case::protected_fields("kdbx-with-protected-custom-fields.kdbx", 1, 1)]
    fn test_other_fields_become_custom_fields_for_v5(
        #[case] name: &str,
        #[case] custom_fields: usize,
        #[case] uris: usize,
    ) {
        let content = read_file(name, Some("passbolt"), true);

        let resource = resources(&content)[0];
        assert_eq!(resource.custom_fields.len(), custom_fields);
        assert_eq!(resource.uris.len(), uris);
        assert_eq!(content.warnings, []);
    }

    #[rstest]
    #[case::custom_fields("kdbx-custom-fields-with-uris.kdbx")]
    #[case::icon("kdbx-protected-with-color-and-icon.kdbx")]
    fn test_v4_resources_get_no_custom_field_nor_icon(#[case] name: &str) {
        let content = read_file(name, Some("passbolt"), false);

        let resource = resources(&content)[0];
        assert_eq!(resource.custom_fields, []);
        assert_eq!(resource.icon, None);
    }

    #[test]
    fn test_a_file_with_empty_times_is_read() {
        let content = read_file("kdbx-with-all-resource-types.kdbx", Some("test"), true);

        assert!(!content.resources.is_empty());
    }
}
