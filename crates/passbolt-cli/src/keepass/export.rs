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

//! Exporting a KDBX file as the browser extension writes it: one group per folder below a
//! `passbolt export` group, one entry per resource.

use anyhow::{Context, Result};
use secstr::SecStr;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Client;
use passbolt_sdk::exchange::export::external_resources;
use passbolt_sdk::exchange::external::ExternalResource;
use passbolt_sdk::resource::view::ResourceView;
use passbolt_sdk::types::Folder;

pub const DATABASE_NAME: &str = "passbolt export";
pub const ROOT_GROUP_NAME: &str = DATABASE_NAME;

/// The fields an entry has whatever the resource; a custom field takes another name.
const ENTRY_FIELDS: [&str; 10] = [
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
const ICON_TYPE_KEEPASS_ICON_SET: &str = "keepass-icon-set";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KdbxVersion {
    /// KDBX 3.1: AES-KDF, AES-256-CBC, Salsa20 protected values.
    V3,
    /// KDBX 4: Argon2, AES-256-CBC, `ChaCha20` protected values.
    V4,
}

impl KdbxVersion {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "v3" => Ok(Self::V3),
            "v4" => Ok(Self::V4),
            _ => Err(format!("invalid kdbx-version {value:?}: must be v3 or v4")),
        }
    }
}

/// Where an entry keeps its TOTP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TotpFormat {
    /// `kdbx`: the `TimeOtp-*` fields of `KeePass`.
    KeePass,
    /// `kdbx-others`: an `otpauth://` URI in an `otp` field, as `KeePassXC` keeps it.
    Others,
}

impl TotpFormat {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "kdbx" => Ok(Self::KeePass),
            "kdbx-others" => Ok(Self::Others),
            _ => Err(format!(
                "invalid format {value:?}: must be kdbx or kdbx-others"
            )),
        }
    }
}

/// How the export file is locked: a password, a key file, both or neither.
pub struct Credentials<'a> {
    pub password: Option<&'a str>,
    pub keyfile: Option<&'a [u8]>,
}

/// Export Passbolt resources to a `KeePass` KDBX file, preserving folder hierarchy.
///
/// If `folder_id` is provided, only resources inside that folder subtree are exported.
/// The resources are listed as `list resource` lists them, their secrets decrypted by
/// `workers` threads (0 = one per CPU). A resource that cannot be decrypted is reported
/// and skipped.
pub async fn export_keepass(
    client: &Client,
    output_path: &Path,
    credentials: &Credentials<'_>,
    version: KdbxVersion,
    totp_format: TotpFormat,
    folder_id: Option<&str>,
    workers: usize,
) -> Result<()> {
    if output_path.as_os_str().is_empty() {
        anyhow::bail!("the Filename cannot be empty");
    }
    println!("Getting Resources...");
    let (views, folders) = crate::cli::export::exported(client, folder_id, workers).await?;

    let (entries, skipped, renamed) = collect_entries(&views, &folders, totp_format);
    for reason in &skipped {
        println!("\n{reason}");
    }
    for field in &renamed {
        eprintln!(
            "Warning: the custom field {:?} of {} is exported as {:?}",
            field.original_key, field.resource_name, field.new_key
        );
    }
    let root = build_tree(entries, &folders);

    match version {
        KdbxVersion::V3 => {
            let composite_key =
                super::kdbx::composite_key(credentials.password, credentials.keyfile)?;
            save_replacing(output_path, |file| {
                super::kdbx3::write_kdbx3(file, &composite_key, &root)
                    .with_context(|| format!("Cannot write KDBX to {}", output_path.display()))
            })
        }
        KdbxVersion::V4 => write_kdbx4(output_path, credentials, &root),
    }?;

    println!("Done");
    Ok(())
}

/// A custom field exported under another name, its own being taken.
#[derive(Debug, PartialEq, Eq)]
pub struct RenamedField {
    pub resource_name: String,
    pub original_key: String,
    pub new_key: String,
}

type FolderEntries = Vec<(Option<String>, KeePassEntry)>;

/// The entries of the decrypted views, with their folder; the views that could not be
/// decrypted are skipped, the reasons returned instead, with the renamed custom fields.
fn collect_entries(
    views: &[ResourceView],
    folders: &[Folder],
    totp_format: TotpFormat,
) -> (FolderEntries, Vec<String>, Vec<RenamedField>) {
    let (readable, unreadable): (Vec<&ResourceView>, Vec<&ResourceView>) =
        views.iter().partition(|view| view.error.is_none());
    let skipped = unreadable
        .iter()
        .map(|view| {
            format!(
                "Skipping Export of Resource {} {} Because of: {}",
                view.id,
                view.name,
                view.error.as_deref().unwrap_or_default()
            )
        })
        .collect();
    let readable: Vec<ResourceView> = readable.into_iter().cloned().collect();
    let mut renamed = Vec::new();
    let entries = readable
        .iter()
        .zip(external_resources(&readable, folders))
        .map(|(view, resource)| {
            let entry = build_entry(&resource, totp_format, &mut renamed);
            (view.folder_parent_id.clone(), entry)
        })
        .collect();
    (entries, skipped, renamed)
}

/// A string field of an entry; zeroized on drop so decrypted secrets do not linger in the
/// heap after the KDBX file is written.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EntryField {
    pub key: String,
    pub value: String,
    #[zeroize(skip)]
    pub protected: bool,
}

/// An entry: its string fields in the order `KeePass` lists them, its expiry and its icon.
#[derive(Default)]
pub struct KeePassEntry {
    pub fields: Vec<EntryField>,
    pub expiry: Option<chrono::DateTime<chrono::Utc>>,
    pub icon_id: Option<u32>,
    /// `#RRGGBB`.
    pub background_color: Option<String>,
}

impl KeePassEntry {
    #[must_use]
    pub fn field(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|field| field.key == key)
            .map(|field| field.value.as_str())
    }

    fn set(&mut self, key: &str, value: &str, protected: bool) {
        self.fields.push(EntryField {
            key: key.to_owned(),
            value: value.to_owned(),
            protected,
        });
    }
}

/// A `KeePass` group: a Passbolt folder, or the root of the export.
pub struct KeePassGroup {
    pub name: String,
    pub entries: Vec<KeePassEntry>,
    pub groups: Vec<Self>,
}

impl KeePassGroup {
    pub fn named(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            entries: Vec::new(),
            groups: Vec::new(),
        }
    }
}

/// The entry of `resource`: the title, user name, password, URL and notes, its TOTP, its
/// other URLs as `KP2A_URL` fields, then its custom fields, protected.
fn build_entry(
    resource: &ExternalResource,
    totp_format: TotpFormat,
    renamed: &mut Vec<RenamedField>,
) -> KeePassEntry {
    let mut entry = KeePassEntry::default();
    entry.set("Title", &resource.name, false);
    entry.set(
        "UserName",
        resource.username.as_deref().unwrap_or_default(),
        false,
    );
    entry.set("Password", &resource.secret_clear, true);
    entry.set(
        "URL",
        resource
            .uris
            .first()
            .map(String::as_str)
            .unwrap_or_default(),
        false,
    );
    entry.set(
        "Notes",
        resource.description.as_deref().unwrap_or_default(),
        false,
    );
    set_totp(&mut entry, resource, totp_format);
    for (index, uri) in resource.uris.iter().enumerate().skip(1) {
        let key = if index == 1 {
            "KP2A_URL".to_owned()
        } else {
            format!("KP2A_URL_{index}")
        };
        entry.set(&key, uri, false);
    }
    for field in &resource.custom_fields {
        let original_key = field.metadata_key.clone().unwrap_or_default();
        let key = free_field_name(&entry, &original_key);
        if key != original_key {
            renamed.push(RenamedField {
                resource_name: resource.name.clone(),
                original_key,
                new_key: key.clone(),
            });
        }
        let value = field
            .secret_value
            .as_ref()
            .or(field.metadata_value.as_ref())
            .map(|value| {
                value
                    .as_str()
                    .map_or_else(|| value.to_string(), String::from)
            })
            .unwrap_or_default();
        entry.set(&key, &value, true);
    }
    entry.expiry = resource
        .expired
        .as_deref()
        .and_then(|expired| chrono::DateTime::parse_from_rfc3339(expired).ok())
        .map(|expired| expired.with_timezone(&chrono::Utc));
    if let Some(icon) = &resource.icon {
        if icon.get("type").and_then(serde_json::Value::as_str) == Some(ICON_TYPE_KEEPASS_ICON_SET)
        {
            entry.icon_id = icon
                .get("value")
                .and_then(serde_json::Value::as_u64)
                .and_then(|value| u32::try_from(value).ok());
        }
        entry.background_color = icon
            .get("background_color")
            .and_then(serde_json::Value::as_str)
            .map(String::from);
    }
    entry
}

fn set_totp(entry: &mut KeePassEntry, resource: &ExternalResource, totp_format: TotpFormat) {
    let Some(totp) = &resource.totp else {
        return;
    };
    match totp_format {
        TotpFormat::KeePass => {
            // SHA256 → HMAC-SHA-256
            let algorithm = totp.algorithm.as_deref().unwrap_or("SHA1");
            let (family, size) = algorithm.split_at(algorithm.len().min(3));
            entry.set(
                "TimeOtp-Secret-Base32",
                totp.secret_key.as_deref().unwrap_or_default(),
                true,
            );
            entry.set("TimeOtp-Algorithm", &format!("HMAC-{family}-{size}"), false);
            entry.set(
                "TimeOtp-Length",
                &totp.digits.unwrap_or(6).to_string(),
                false,
            );
            entry.set(
                "TimeOtp-Period",
                &totp.period.unwrap_or(30).to_string(),
                false,
            );
        }
        TotpFormat::Others => {
            if let Some(uri) = resource.totp_uri() {
                entry.set("otp", &uri, true);
            }
        }
    }
}

/// `key`, else `key (1)`, `key (2)`… when an entry field or a field of `entry` has it.
fn free_field_name(entry: &KeePassEntry, key: &str) -> String {
    let taken = |name: &str| ENTRY_FIELDS.contains(&name) || entry.field(name).is_some();
    if !taken(key) {
        return key.to_owned();
    }
    let mut index = 1;
    while taken(&format!("{key} ({index})")) {
        index += 1;
    }
    format!("{key} ({index})")
}

/// The `root` group: the entries without folder and one sub-group per folder, nested as
/// the folders are.
fn build_tree(entries: Vec<(Option<String>, KeePassEntry)>, folders: &[Folder]) -> KeePassGroup {
    let mut root = KeePassGroup::named(ROOT_GROUP_NAME);
    let bfs_order = bfs_folders(folders);
    let mut groups: HashMap<&str, KeePassGroup> = bfs_order
        .iter()
        .map(|folder| (folder.id.as_str(), KeePassGroup::named(&folder.name)))
        .collect();

    for (folder_id, entry) in entries {
        match folder_id.as_deref().and_then(|id| groups.get_mut(id)) {
            Some(group) => group.entries.push(entry),
            None => root.entries.push(entry),
        }
    }

    // Deepest first, so that a group is complete when it joins its parent.
    for folder in bfs_order.iter().rev() {
        if let Some(group) = groups.remove(folder.id.as_str()) {
            let parent = folder
                .folder_parent_id
                .as_deref()
                .and_then(|parent_id| groups.get_mut(parent_id))
                .unwrap_or(&mut root);
            parent.groups.insert(0, group);
        }
    }
    root
}

fn write_kdbx4(path: &Path, credentials: &Credentials<'_>, root: &KeePassGroup) -> Result<()> {
    use keepass::{config::DatabaseConfig, db::Database, DatabaseKey};

    let mut key = DatabaseKey::new();
    if let Some(password) = credentials.password {
        key = key.with_password(password);
    }
    if let Some(mut keyfile) = credentials.keyfile {
        key = key.with_keyfile(&mut keyfile)?;
    }
    if credentials.password.is_none() && credentials.keyfile.is_none() {
        anyhow::bail!("A KDBX 4 file needs a password or a key file");
    }
    let mut database = Database::new(DatabaseConfig::default());
    database.meta.database_name = Some(DATABASE_NAME.into());
    database.root = keepass_group(root);

    save_replacing(path, |file| {
        database
            .save(file, key)
            .with_context(|| format!("Cannot write KDBX to {}", path.display()))
    })
}

fn keepass_group(group: &KeePassGroup) -> keepass::db::Group {
    use keepass::db::{Entry, Group, Node, Value};

    let mut converted = Group::new(&group.name);
    for entry in &group.entries {
        let mut converted_entry = Entry::new();
        for field in &entry.fields {
            let value = if field.protected {
                Value::Protected(SecStr::from(field.value.as_str()))
            } else {
                Value::Unprotected(field.value.clone())
            };
            converted_entry.fields.insert(field.key.clone(), value);
        }
        if let Some(expiry) = entry.expiry {
            converted_entry.times.expires = true;
            converted_entry.times.set_expiry(expiry.naive_utc());
        }
        converted_entry.icon_id = entry.icon_id.map(|icon_id| icon_id as usize);
        converted_entry.background_color = entry
            .background_color
            .as_deref()
            .and_then(|color| color.parse().ok());
        converted.children.push(Node::Entry(converted_entry));
    }
    for child in &group.groups {
        converted.children.push(Node::Group(keepass_group(child)));
    }
    converted
}

/// Write a sibling file then rename it over `path`: a failed export never damages the
/// previous one. The file is readable by its owner only on Unix.
pub fn save_replacing(
    path: &Path,
    write: impl FnOnce(&mut std::fs::File) -> Result<()>,
) -> Result<()> {
    let file_name = path
        .file_name()
        .with_context(|| format!("{} is not a file path", path.display()))?;
    let temporary = path.with_file_name(format!(
        ".{}.{}.tmp",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let written = options
        .open(&temporary)
        .with_context(|| format!("Cannot create {}", temporary.display()))
        .and_then(|mut file| {
            write(&mut file)?;
            file.sync_all().context("Cannot flush the export")
        })
        .and_then(|()| {
            std::fs::rename(&temporary, path)
                .with_context(|| format!("Cannot replace {}", path.display()))
        });
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    written
}

/// Return folders in BFS order (parents before children). A folder whose
/// parent is not in `folders` is a root, so an exported sub-folder keeps its tree.
fn bfs_folders(folders: &[Folder]) -> Vec<&Folder> {
    let exported_ids: HashSet<&str> = folders.iter().map(|folder| folder.id.as_str()).collect();
    let mut result: Vec<&Folder> = Vec::with_capacity(folders.len());
    let mut queue: VecDeque<&Folder> = folders
        .iter()
        .filter(|folder| {
            folder
                .folder_parent_id
                .as_deref()
                .is_none_or(|parent_id| !exported_ids.contains(parent_id))
        })
        .collect();

    while let Some(folder) = queue.pop_front() {
        result.push(folder);
        for child in folders.iter().filter(|candidate| {
            candidate
                .folder_parent_id
                .as_deref()
                .is_some_and(|parent_id| parent_id == folder.id)
        }) {
            queue.push_back(child);
        }
    }

    // Append the folders of a parent cycle, unreachable from any root, so they're not lost
    for folder in folders {
        if !result.iter().any(|added| added.id == folder.id) {
            result.push(folder);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::db::{Database, Node, Value};
    use keepass::DatabaseKey;
    use passbolt_sdk::exchange::external::totp_with_defaults;
    use passbolt_sdk::types::{CustomField, Resource, ResourceType};
    use rstest::rstest;
    use serde_json::json;

    fn make_resource(name: &str) -> Resource {
        Resource {
            id: format!("{name}-id"),
            name: name.into(),
            username: None,
            uri: None,
            description: None,
            folder_parent_id: None,
            resource_type_id: Some("password-and-description-id".into()),
            created: None,
            modified: None,
            created_by: None,
            modified_by: None,
            personal: None,
            favorite: None,
            secrets: vec![],
            permission: None,
            permissions: vec![],
            tags: vec![],
            metadata_armored: None,
            metadata_key_id: None,
            metadata_key_type: None,
            expired: None,
            deleted: None,
        }
    }

    fn make_folder(id: &str, parent_id: Option<&str>) -> Folder {
        Folder {
            id: id.into(),
            name: format!("{id}-name"),
            folder_parent_id: parent_id.map(Into::into),
            created: None,
            modified: None,
            created_by: None,
            modified_by: None,
            personal: None,
            permission: None,
            permissions: vec![],
        }
    }

    fn make_entry(title: &str) -> KeePassEntry {
        let mut entry = KeePassEntry::default();
        entry.set("Title", title, false);
        entry.set("Password", &format!("{title}-password"), true);
        entry
    }

    fn external(name: &str) -> ExternalResource {
        ExternalResource {
            name: name.into(),
            username: Some("ada".into()),
            uris: vec!["https://a.test".into()],
            description: Some("notes".into()),
            secret_clear: "secret".into(),
            ..ExternalResource::default()
        }
    }

    fn text_field(key: &str, value: &str) -> CustomField {
        CustomField {
            id: key.into(),
            field_type: "text".into(),
            metadata_key: Some(key.into()),
            metadata_value: None,
            secret_key: None,
            secret_value: Some(json!(value)),
        }
    }

    fn entry_of(resource: &ExternalResource, totp_format: TotpFormat) -> KeePassEntry {
        build_entry(resource, totp_format, &mut Vec::new())
    }

    fn field_triples(entry: &KeePassEntry) -> Vec<(&str, &str, bool)> {
        entry
            .fields
            .iter()
            .map(|field| (field.key.as_str(), field.value.as_str(), field.protected))
            .collect()
    }

    fn folder_ids<'a>(folders: &[&'a Folder]) -> Vec<&'a str> {
        folders.iter().map(|folder| folder.id.as_str()).collect()
    }

    fn group_names(group: &KeePassGroup) -> Vec<&str> {
        group
            .groups
            .iter()
            .map(|child| child.name.as_str())
            .collect()
    }

    fn entry_titles(group: &KeePassGroup) -> Vec<&str> {
        group
            .entries
            .iter()
            .map(|entry| entry.field("Title").unwrap())
            .collect()
    }

    fn types() -> Vec<ResourceType> {
        vec![ResourceType {
            id: "password-and-description-id".into(),
            slug: "password-and-description".into(),
            name: None,
            definition: None,
        }]
    }

    #[test]
    fn test_kdbx_version_parse_accepts_v3_and_v4() {
        assert_eq!(KdbxVersion::parse("v3"), Ok(KdbxVersion::V3));
        assert_eq!(KdbxVersion::parse("v4"), Ok(KdbxVersion::V4));
    }

    #[test]
    fn test_kdbx_version_parse_rejects_others() {
        assert_eq!(
            KdbxVersion::parse("4"),
            Err(r#"invalid kdbx-version "4": must be v3 or v4"#.to_string())
        );
    }

    #[rstest]
    #[case::keepass("kdbx", Ok(TotpFormat::KeePass))]
    #[case::others("kdbx-others", Ok(TotpFormat::Others))]
    #[case::unknown("csv", Err(r#"invalid format "csv": must be kdbx or kdbx-others"#.to_string()))]
    fn test_totp_format_parse(#[case] value: &str, #[case] expected: Result<TotpFormat, String>) {
        assert_eq!(TotpFormat::parse(value), expected);
    }

    #[test]
    fn test_an_entry_lists_the_fields_of_the_resource_in_order() {
        let entry = entry_of(&external("site"), TotpFormat::Others);

        assert_eq!(
            field_triples(&entry),
            [
                ("Title", "site", false),
                ("UserName", "ada", false),
                ("Password", "secret", true),
                ("URL", "https://a.test", false),
                ("Notes", "notes", false),
            ]
        );
    }

    #[test]
    fn test_the_other_uris_become_kp2a_url_fields() {
        let resource = ExternalResource {
            uris: vec![
                "https://1.test".into(),
                "https://2.test".into(),
                "https://3.test".into(),
            ],
            ..external("site")
        };

        let entry = entry_of(&resource, TotpFormat::Others);

        assert_eq!(entry.field("URL"), Some("https://1.test"));
        assert_eq!(entry.field("KP2A_URL"), Some("https://2.test"));
        assert_eq!(entry.field("KP2A_URL_2"), Some("https://3.test"));
    }

    #[rstest]
    #[case::keepass(TotpFormat::KeePass, &[
        ("TimeOtp-Secret-Base32", "JBSWY3DP", true),
        ("TimeOtp-Algorithm", "HMAC-SHA-256", false),
        ("TimeOtp-Length", "8", false),
        ("TimeOtp-Period", "60", false),
    ])]
    #[case::others(TotpFormat::Others, &[(
        "otp",
        "otpauth://totp/site%3Aada?secret=JBSWY3DP&issuer=https%253A%252F%252Fa.test&algorithm=SHA256&digits=8&period=60",
        true,
    )])]
    fn test_the_totp_is_written_in_the_fields_of_the_format(
        #[case] totp_format: TotpFormat,
        #[case] expected: &[(&str, &str, bool)],
    ) {
        let resource = ExternalResource {
            totp: Some(totp_with_defaults(
                "JBSWY3DP",
                Some("SHA256".into()),
                Some(8),
                Some(60),
            )),
            ..external("site")
        };

        let entry = entry_of(&resource, totp_format);

        assert_eq!(field_triples(&entry)[5..], *expected);
    }

    #[test]
    fn test_custom_fields_are_protected_and_renamed_when_their_name_is_taken() {
        let resource = ExternalResource {
            custom_fields: vec![
                text_field("Account", "42"),
                text_field("Password", "custom"),
                text_field("Account", "43"),
            ],
            ..external("bank")
        };
        let mut renamed = Vec::new();

        let entry = build_entry(&resource, TotpFormat::Others, &mut renamed);

        assert_eq!(
            field_triples(&entry)[5..],
            [
                ("Account", "42", true),
                ("Password (1)", "custom", true),
                ("Account (1)", "43", true),
            ]
        );
        assert_eq!(
            renamed[0],
            RenamedField {
                resource_name: "bank".into(),
                original_key: "Password".into(),
                new_key: "Password (1)".into(),
            }
        );
        assert_eq!(renamed.len(), 2);
    }

    #[test]
    fn test_the_expiry_and_the_icon_are_kept() {
        let resource = ExternalResource {
            expired: Some("2030-01-31T12:00:00+00:00".into()),
            icon: Some(
                json!({"type": "keepass-icon-set", "value": 4, "background_color": "#FF0000"}),
            ),
            ..external("site")
        };

        let entry = entry_of(&resource, TotpFormat::Others);

        assert_eq!(
            entry.expiry.map(|expiry| expiry.to_rfc3339()),
            Some("2030-01-31T12:00:00+00:00".into())
        );
        assert_eq!(entry.icon_id, Some(4));
        assert_eq!(entry.background_color.as_deref(), Some("#FF0000"));
    }

    #[rstest]
    #[case::full_vault(
        vec![make_folder("child", Some("top")), make_folder("top", None)],
        vec!["top", "child"]
    )]
    #[case::subtree_root_listed_after_child(
        vec![make_folder("child", Some("sub")), make_folder("sub", Some("outside"))],
        vec!["sub", "child"]
    )]
    #[case::cycle_kept(
        vec![make_folder("first", Some("second")), make_folder("second", Some("first"))],
        vec!["first", "second"]
    )]
    fn test_bfs_folders_orders_parents_first(
        #[case] folders: Vec<Folder>,
        #[case] expected: Vec<&str>,
    ) {
        assert_eq!(folder_ids(&bfs_folders(&folders)), expected);
    }

    #[test]
    fn test_build_tree_puts_everything_in_the_passbolt_export_group() {
        let root = build_tree(vec![(None, make_entry("loose"))], &[]);

        assert_eq!(root.name, "passbolt export");
        assert_eq!(entry_titles(&root), ["loose"]);
    }

    #[test]
    fn test_build_tree_keeps_hierarchy_of_exported_subtree() {
        let folders = vec![
            make_folder("child", Some("sub")),
            make_folder("sub", Some("outside")),
        ];
        let entries = vec![
            (None, make_entry("at-root")),
            (Some("child".to_owned()), make_entry("nested")),
            (Some("unknown".to_owned()), make_entry("orphan")),
        ];

        let root = build_tree(entries, &folders);

        assert_eq!(entry_titles(&root), ["at-root", "orphan"]);
        assert_eq!(group_names(&root), ["sub-name"]);
        assert_eq!(group_names(&root.groups[0]), ["child-name"]);
        assert_eq!(entry_titles(&root.groups[0].groups[0]), ["nested"]);
    }

    #[test]
    fn test_build_tree_keeps_the_folder_order() {
        let folders = vec![make_folder("first", None), make_folder("second", None)];

        let root = build_tree(Vec::new(), &folders);

        assert_eq!(group_names(&root), ["first-name", "second-name"]);
    }

    #[test]
    fn test_build_tree_keeps_folders_of_a_cycle() {
        let folders = vec![
            make_folder("first", Some("second")),
            make_folder("second", Some("first")),
        ];

        let root = build_tree(Vec::new(), &folders);

        assert_eq!(group_names(&root), ["first-name"]);
        assert_eq!(group_names(&root.groups[0]), ["second-name"]);
    }

    #[test]
    fn test_collect_entries_skips_failures_with_their_reason() {
        let decrypted = ResourceView::new(make_resource("decrypted"), None, &types())
            .unwrap()
            .with_secret(r#"{"password":"p4ss","description":"notes"}"#)
            .unwrap();
        let broken = ResourceView::new(make_resource("broken"), None, &types())
            .unwrap()
            .with_error(&passbolt_sdk::PassboltError::Other("no key".into()));

        let (entries, skipped, _) = collect_entries(&[decrypted, broken], &[], TotpFormat::Others);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1.field("Password"), Some("p4ss"));
        assert_eq!(entries[0].1.field("Notes"), Some("notes"));
        assert_eq!(
            skipped,
            ["Skipping Export of Resource broken-id broken Because of: no key"]
        );
    }

    #[test]
    fn test_write_kdbx4_writes_the_tree() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("export.kdbx");
        let mut root = KeePassGroup::named(ROOT_GROUP_NAME);
        let mut folder = KeePassGroup::named("folder");
        let mut entry = make_entry("nested");
        entry.set("Account", "42", true);
        folder.entries.push(entry);
        root.groups.push(folder);
        let credentials = Credentials {
            password: Some("master"),
            keyfile: None,
        };

        write_kdbx4(&path, &credentials, &root).unwrap();

        let database = Database::open(
            &mut std::fs::File::open(&path).unwrap(),
            DatabaseKey::new().with_password("master"),
        )
        .unwrap();
        assert_eq!(
            database.config.version,
            keepass::config::DatabaseVersion::KDB4(0)
        );
        assert_eq!(
            database.meta.database_name.as_deref(),
            Some("passbolt export")
        );
        let Some(Node::Group(folder)) = database.root.children.first() else {
            panic!("no folder group");
        };
        let Some(Node::Entry(entry)) = folder.children.first() else {
            panic!("no entry");
        };
        assert_eq!(entry.get_password(), Some("nested-password"));
        assert!(matches!(
            entry.fields.get("Account"),
            Some(Value::Protected(_))
        ));
    }

    #[test]
    fn test_write_kdbx4_refuses_a_file_without_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let credentials = Credentials {
            password: None,
            keyfile: None,
        };

        let error = write_kdbx4(
            &directory.path().join("export.kdbx"),
            &credentials,
            &KeePassGroup::named(ROOT_GROUP_NAME),
        )
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            "A KDBX 4 file needs a password or a key file"
        );
    }

    #[test]
    fn test_save_replacing_keeps_the_previous_file_when_writing_fails() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("backup.kdbx");
        std::fs::write(&path, "previous backup").unwrap();

        let result = save_replacing(&path, |_| anyhow::bail!("disk full"));

        assert!(result.is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "previous backup");
        assert_eq!(
            std::fs::read_dir(directory.path()).unwrap().count(),
            1,
            "temporary file left"
        );
    }

    #[test]
    fn test_save_replacing_replaces_the_file() {
        use std::io::Write;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("backup.kdbx");
        std::fs::write(&path, "previous backup").unwrap();

        save_replacing(&path, |file| Ok(file.write_all(b"new backup")?)).unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new backup");
    }
}
