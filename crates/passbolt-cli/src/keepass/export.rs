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

use anyhow::{Context, Result};
use indicatif::ProgressBar;
use secstr::SecStr;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::util::resources::custom_fields;
use crate::Client;
use passbolt_sdk::resource::list::list_resources;
use passbolt_sdk::resource::view::ResourceView;
use passbolt_sdk::types::{Folder, TotpData};

pub const DATABASE_NAME: &str = "Passbolt Export";
pub const ROOT_GROUP_NAME: &str = "root";

const STANDARD_FIELDS: [&str; 6] = ["Title", "UserName", "URL", "Password", "Notes", "otp"];

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

/// Export Passbolt resources to a `KeePass` KDBX file, preserving folder hierarchy.
///
/// If `folder_id` is provided, only resources inside that folder subtree are exported.
/// The resources are listed as `list resource` lists them, their secrets decrypted by
/// `workers` threads (0 = one per CPU). A resource that cannot be decrypted is reported
/// and skipped, as go-passbolt-cli does.
pub async fn export_keepass(
    client: &Client,
    output_path: &Path,
    password: &str,
    version: KdbxVersion,
    folder_id: Option<&str>,
    workers: usize,
) -> Result<()> {
    if output_path.as_os_str().is_empty() {
        anyhow::bail!("the Filename cannot be empty");
    }
    let all_folders = client
        .get_folders(passbolt_sdk::FolderQuery::default())
        .await
        .context("Failed to fetch folders")?;

    let (query, folders) = match folder_id {
        Some(root_id) => {
            if !all_folders.iter().any(|folder| folder.id == root_id) {
                anyhow::bail!("folder {root_id} not found");
            }
            let subtree_ids = passbolt_sdk::collect_subtree_ids(root_id, &all_folders);
            let query = passbolt_sdk::ResourceQuery {
                folder_ids: subtree_ids.iter().cloned().collect(),
                ..Default::default()
            };
            let folders: Vec<Folder> = all_folders
                .into_iter()
                .filter(|folder| subtree_ids.contains(&folder.id))
                .collect();
            (query, folders)
        }
        None => (passbolt_sdk::ResourceQuery::default(), all_folders),
    };

    println!("Getting Resources...");
    let progress = ProgressBar::new_spinner().with_message("Decrypting Resources");
    progress.enable_steady_tick(std::time::Duration::from_millis(100));
    let views = list_resources(client, query, &[], Some(workers))
        .await
        .context("getting Resources")?;
    progress.finish_and_clear();

    let (entries, skipped) = collect_entries(&views);
    for reason in &skipped {
        println!("\n{reason}");
    }
    let root = build_tree(entries, &folders);

    match version {
        KdbxVersion::V3 => save_replacing(output_path, |file| {
            super::kdbx3::write_kdbx3(file, password, &root)
                .with_context(|| format!("Cannot write KDBX to {}", output_path.display()))
        }),
        KdbxVersion::V4 => write_kdbx4(output_path, password, &root),
    }?;

    println!("Done");
    Ok(())
}

/// The entries of the decrypted views, with their folder; the views that could not be
/// decrypted are skipped, the reasons returned instead.
fn collect_entries(views: &[ResourceView]) -> (Vec<(Option<String>, KeePassEntry)>, Vec<String>) {
    let mut entries = Vec::with_capacity(views.len());
    let mut skipped = Vec::new();
    for view in views {
        match &view.error {
            None => entries.push((view.folder_parent_id.clone(), build_entry(view))),
            Some(error) => skipped.push(format!(
                "Skipping Export of Resource {} {} Because of: {error}",
                view.id, view.name
            )),
        }
    }
    (entries, skipped)
}

/// Intermediate plaintext representation; zeroized on drop so decrypted
/// passwords do not linger in the heap after the KDBX file is written.
#[derive(ZeroizeOnDrop)]
pub struct KeePassEntry {
    pub title: String,
    pub username: String,
    pub url: String,
    pub password: String,
    pub notes: String,
    pub otp: Option<String>,
    pub custom_fields: Vec<CustomField>,
}

#[derive(Zeroize)]
pub struct CustomField {
    pub name: String,
    pub value: String,
}

/// A string field of an entry, in the order `KeePass` lists them.
pub struct EntryField<'a> {
    pub key: &'a str,
    pub value: &'a str,
    pub protected: bool,
}

impl KeePassEntry {
    pub fn fields(&self) -> Vec<EntryField<'_>> {
        let field = |key, value, protected| EntryField {
            key,
            value,
            protected,
        };
        let mut fields = vec![
            field("Title", self.title.as_str(), false),
            field("UserName", self.username.as_str(), false),
            field("URL", self.url.as_str(), false),
            field("Password", self.password.as_str(), true),
            field("Notes", self.notes.as_str(), false),
        ];
        if let Some(otp) = &self.otp {
            fields.push(field("otp", otp.as_str(), true));
        }
        for custom_field in &self.custom_fields {
            fields.push(field(
                custom_field.name.as_str(),
                custom_field.value.as_str(),
                true,
            ));
        }
        fields
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

fn build_entry(view: &ResourceView) -> KeePassEntry {
    // The v5 note is the secret description, after the public one.
    let notes = [view.description.as_str(), view.note().unwrap_or_default()]
        .into_iter()
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>()
        .join("\n\n");
    let otp = view
        .secret
        .as_ref()
        .and_then(|secret| secret.get("totp"))
        .and_then(|totp| serde_json::from_value::<TotpData>(totp.clone()).ok())
        .and_then(|totp| build_otpauth(&view.name, &view.username, &view.uri, &totp));

    KeePassEntry {
        title: view.name.clone(),
        username: view.username.clone(),
        url: view.uri.clone(),
        password: view.password.clone().unwrap_or_default(),
        notes,
        otp,
        custom_fields: entry_custom_fields(view),
    }
}

/// The custom fields, each named after its key. A name taken by a standard field or an
/// earlier custom field gets a ` (2)`, ` (3)`… suffix: a `KeePass` entry has unique keys.
fn entry_custom_fields(view: &ResourceView) -> Vec<CustomField> {
    let secret_side = view
        .secret
        .as_ref()
        .and_then(|secret| secret.get("custom_fields"));
    let mut taken: HashSet<String> = STANDARD_FIELDS.iter().map(|&name| name.into()).collect();
    custom_fields(view.metadata.get("custom_fields"), secret_side)
        .into_iter()
        .filter(|(name, _)| !name.is_empty())
        .map(|(name, value)| CustomField {
            name: unique_field_name(&name, &mut taken),
            value,
        })
        .collect()
}

fn unique_field_name(name: &str, taken: &mut HashSet<String>) -> String {
    let mut candidate = name.to_owned();
    let mut index = 2;
    while !taken.insert(candidate.clone()) {
        candidate = format!("{name} ({index})");
        index += 1;
    }
    candidate
}

/// Normalise a base32 secret: uppercase, strip spaces and `=` padding,
/// which the Key URI format omits.
fn normalize_base32(secret: &str) -> String {
    secret
        .trim()
        .to_uppercase()
        .replace(' ', "")
        .trim_end_matches('=')
        .to_owned()
}

/// Percent-encode everything but the RFC 3986 unreserved characters.
fn percent_encode(value: &str) -> String {
    const HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX_DIGITS[usize::from(byte & 0x0F)]));
        }
    }
    encoded
}

/// Build an `otpauth://totp/issuer:account` URI (Google Key URI format) for the
/// `KeePass` OTP plugin, or `None` without a secret key. As go-passbolt-cli, the issuer is
/// the URI, else the title; the account is the username, else the title.
fn build_otpauth(title: &str, username: &str, url: &str, totp: &TotpData) -> Option<String> {
    let secret = normalize_base32(totp.secret_key.as_deref().unwrap_or(""));
    if secret.is_empty() {
        return None;
    }
    let issuer = if url.is_empty() { title } else { url };
    let account = if username.is_empty() { title } else { username };
    let label = format!("{}:{}", percent_encode(issuer), percent_encode(account));
    let algorithm = percent_encode(&totp.algorithm.as_deref().unwrap_or("SHA1").to_uppercase());
    let digits = totp.digits.unwrap_or(6);
    let period = totp.period.unwrap_or(30);

    Some(format!(
        "otpauth://totp/{label}?secret={}&issuer={}&algorithm={algorithm}&digits={digits}&period={period}",
        percent_encode(&secret),
        percent_encode(issuer)
    ))
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

fn write_kdbx4(path: &Path, password: &str, root: &KeePassGroup) -> Result<()> {
    use keepass::{config::DatabaseConfig, db::Database, DatabaseKey};

    let mut database = Database::new(DatabaseConfig::default());
    database.meta.database_name = Some(DATABASE_NAME.into());
    database.root = keepass_group(root);

    let key = DatabaseKey::new().with_password(password);
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
        for field in entry.fields() {
            let value = if field.protected {
                Value::Protected(SecStr::from(field.value))
            } else {
                Value::Unprotected(field.value.to_owned())
            };
            converted_entry.fields.insert(field.key.to_owned(), value);
        }
        converted.children.push(Node::Entry(converted_entry));
    }
    for child in &group.groups {
        converted.children.push(Node::Group(keepass_group(child)));
    }
    converted
}

/// Write a sibling file then rename it over `path`: a failed export never damages the
/// previous one. The file is readable by its owner only on Unix.
fn save_replacing(path: &Path, write: impl FnOnce(&mut std::fs::File) -> Result<()>) -> Result<()> {
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
    use passbolt_sdk::types::{Resource, ResourceMetadata, ResourceType};
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
            resource_type_id: None,
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

    fn make_totp(secret: &str) -> TotpData {
        serde_json::from_value(json!({
            "secret_key": secret, "algorithm": "SHA1", "digits": 6, "period": 30
        }))
        .unwrap()
    }

    fn make_entry(title: &str) -> KeePassEntry {
        KeePassEntry {
            title: title.into(),
            username: String::new(),
            url: String::new(),
            password: format!("{title}-password"),
            notes: String::new(),
            otp: None,
            custom_fields: Vec::new(),
        }
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
            .map(|entry| entry.title.as_str())
            .collect()
    }

    fn types() -> Vec<ResourceType> {
        [
            "password-string",
            "password-and-description",
            "v5-default",
            "v5-default-with-totp",
        ]
        .into_iter()
        .map(|slug| ResourceType {
            id: format!("{slug}-id"),
            slug: slug.into(),
            name: None,
            definition: None,
        })
        .collect()
    }

    fn typed_resource(name: &str, slug: &str) -> Resource {
        Resource {
            resource_type_id: Some(format!("{slug}-id")),
            ..make_resource(name)
        }
    }

    fn view_of(resource: Resource, secret: &str) -> ResourceView {
        ResourceView::new(resource, None, &types())
            .unwrap()
            .with_secret(secret)
            .unwrap()
    }

    fn v5_view_of(metadata: serde_json::Value, secret: &serde_json::Value) -> ResourceView {
        let metadata: ResourceMetadata = serde_json::from_value(metadata).unwrap();
        ResourceView::new(
            typed_resource("ignored", "v5-default-with-totp"),
            Some(metadata),
            &types(),
        )
        .unwrap()
        .with_secret(&secret.to_string())
        .unwrap()
    }

    fn field_pairs(entry: &KeePassEntry) -> Vec<(&str, &str, bool)> {
        entry
            .fields()
            .into_iter()
            .map(|field| (field.key, field.value, field.protected))
            .collect()
    }

    #[test]
    fn test_kdbx_version_parse_accepts_v3_and_v4() {
        assert_eq!(KdbxVersion::parse("v3"), Ok(KdbxVersion::V3));
        assert_eq!(KdbxVersion::parse("v4"), Ok(KdbxVersion::V4));
    }

    #[test]
    fn test_kdbx_version_parse_rejects_others_as_go_passbolt_cli() {
        assert_eq!(
            KdbxVersion::parse("4"),
            Err(r#"invalid kdbx-version "4": must be v3 or v4"#.to_string())
        );
    }

    #[rstest]
    #[case::already_aligned("JBSWY3DPEHPK3PXP", "JBSWY3DPEHPK3PXP")]
    #[case::padding_removed("JBSWY3D=", "JBSWY3D")]
    #[case::lowercase("jbswy3dp", "JBSWY3DP")]
    #[case::spaces("JBSWY 3DP", "JBSWY3DP")]
    #[case::empty("", "")]
    fn test_normalize_base32(#[case] secret: &str, #[case] expected: &str) {
        assert_eq!(normalize_base32(secret), expected);
    }

    #[rstest]
    #[case::issuer_is_the_uri(
        "MyService",
        "alice",
        "https://my.test",
        make_totp("JBSWY3DPEHPK3PXP"),
        "otpauth://totp/https%3A%2F%2Fmy.test:alice?secret=JBSWY3DPEHPK3PXP&issuer=https%3A%2F%2Fmy.test&algorithm=SHA1&digits=6&period=30"
    )]
    #[case::issuer_falls_back_to_the_title(
        "Fallback",
        "bob",
        "",
        make_totp("JBSWY3DP"),
        "otpauth://totp/Fallback:bob?secret=JBSWY3DP&issuer=Fallback&algorithm=SHA1&digits=6&period=30"
    )]
    #[case::special_characters(
        "A&B?C#D:E/F G",
        "me&you?#a:b/c",
        "",
        make_totp("jbswy3d="),
        "otpauth://totp/A%26B%3FC%23D%3AE%2FF%20G:me%26you%3F%23a%3Ab%2Fc?secret=JBSWY3D&issuer=A%26B%3FC%23D%3AE%2FF%20G&algorithm=SHA1&digits=6&period=30"
    )]
    #[case::defaults(
        "My Service",
        "",
        "",
        TotpData { secret_key: Some("JBSWY3DP".into()), ..make_totp("") },
        "otpauth://totp/My%20Service:My%20Service?secret=JBSWY3DP&issuer=My%20Service&algorithm=SHA1&digits=6&period=30"
    )]
    fn test_build_otpauth(
        #[case] title: &str,
        #[case] username: &str,
        #[case] url: &str,
        #[case] totp: TotpData,
        #[case] expected: &str,
    ) {
        assert_eq!(
            build_otpauth(title, username, url, &totp).as_deref(),
            Some(expected)
        );
    }

    #[rstest]
    #[case::empty("")]
    #[case::only_padding(" = ")]
    fn test_build_otpauth_skips_a_totp_without_secret_key(#[case] secret: &str) {
        assert_eq!(build_otpauth("name", "", "", &make_totp(secret)), None);
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
    fn test_build_tree_puts_everything_in_a_root_group() {
        let root = build_tree(vec![(None, make_entry("loose"))], &[]);

        assert_eq!(root.name, "root");
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
    fn test_build_entry_takes_the_password_and_the_description() {
        let view = view_of(
            typed_resource("name", "password-and-description"),
            r#"{"password":"p4ss","description":"notes"}"#,
        );

        let entry = build_entry(&view);

        assert_eq!(
            (entry.password.as_str(), entry.notes.as_str()),
            ("p4ss", "notes")
        );
    }

    #[test]
    fn test_build_entry_keeps_a_password_string_that_looks_like_json() {
        let view = view_of(typed_resource("name", "password-string"), "{}");

        assert_eq!(build_entry(&view).password, "{}");
    }

    #[test]
    fn test_build_entry_never_uses_a_secret_without_password_as_password() {
        let view = view_of(
            typed_resource("name", "v5-default"),
            r#"{"object_type":"PASSBOLT_SECRET_DATA","description":"a note"}"#,
        );

        let entry = build_entry(&view);

        assert_eq!(entry.password, "");
        assert_eq!(entry.notes, "a note");
    }

    #[test]
    fn test_build_entry_exports_custom_fields_as_protected_fields() {
        let view = v5_view_of(
            json!({
                "name": "bank",
                "custom_fields": [
                    {"id": "c1", "type": "text", "metadata_key": "Account"},
                    {"id": "c2", "type": "text", "metadata_key": "Branch", "metadata_value": "Main"},
                ],
            }),
            &json!({
                "object_type": "PASSBOLT_SECRET_DATA",
                "password": "p",
                "custom_fields": [{"id": "c1", "type": "text", "secret_value": "42"}],
            }),
        );

        let entry = build_entry(&view);

        assert_eq!(
            field_pairs(&entry)[5..],
            [("Account", "42", true), ("Branch", "Main", true)]
        );
    }

    #[test]
    fn test_build_entry_renames_custom_fields_with_a_taken_name() {
        let view = v5_view_of(
            json!({
                "name": "bank",
                "custom_fields": [
                    {"id": "c1", "type": "text", "metadata_key": "Password"},
                    {"id": "c2", "type": "text", "metadata_key": "Code"},
                    {"id": "c3", "type": "text", "metadata_key": "Code"},
                    {"id": "c4", "type": "text", "metadata_key": ""},
                ],
            }),
            &json!({
                "object_type": "PASSBOLT_SECRET_DATA",
                "password": "real",
                "custom_fields": [
                    {"id": "c1", "type": "text", "secret_value": "custom"},
                    {"id": "c2", "type": "text", "secret_value": "one"},
                    {"id": "c3", "type": "text", "secret_value": "two"},
                    {"id": "c4", "type": "text", "secret_value": "nameless"},
                ],
            }),
        );

        let entry = build_entry(&view);

        assert_eq!(entry.password, "real");
        assert_eq!(
            field_pairs(&entry)[5..],
            [
                ("Password (2)", "custom", true),
                ("Code", "one", true),
                ("Code (2)", "two", true)
            ]
        );
    }

    #[test]
    fn test_build_entry_builds_the_otp_from_the_uri() {
        let view = v5_view_of(
            json!({"name": "site", "username": "me", "uris": ["https://site.test"]}),
            &json!({
                "object_type": "PASSBOLT_SECRET_DATA",
                "password": "p",
                "totp": {"secret_key": "JBSWY3DP", "algorithm": "SHA256", "digits": 8, "period": 60},
            }),
        );

        let entry = build_entry(&view);

        assert_eq!(
            entry.otp.as_deref(),
            Some("otpauth://totp/https%3A%2F%2Fsite.test:me?secret=JBSWY3DP&issuer=https%3A%2F%2Fsite.test&algorithm=SHA256&digits=8&period=60")
        );
    }

    #[test]
    fn test_entry_fields_list_the_standard_fields_first() {
        let mut entry = make_entry("title");
        entry.otp = Some("otpauth://x".into());

        assert_eq!(
            field_pairs(&entry),
            [
                ("Title", "title", false),
                ("UserName", "", false),
                ("URL", "", false),
                ("Password", "title-password", true),
                ("Notes", "", false),
                ("otp", "otpauth://x", true),
            ]
        );
    }

    #[test]
    fn test_collect_entries_skips_failures_with_the_go_message() {
        let broken = ResourceView::new(make_resource("broken"), None, &types())
            .unwrap()
            .with_error(&passbolt_sdk::PassboltError::Other("no key".into()));
        let views = vec![view_of(make_resource("decrypted"), "secret"), broken];

        let (entries, skipped) = collect_entries(&views);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1.title, "decrypted");
        assert_eq!(
            skipped,
            ["Skipping Export of Resource broken-id broken Because of: no key"]
        );
    }

    #[test]
    fn test_write_kdbx4_writes_the_tree() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("export.kdbx");
        let mut root = KeePassGroup::named("root");
        let mut folder = KeePassGroup::named("folder");
        let mut entry = make_entry("nested");
        entry.custom_fields.push(CustomField {
            name: "Account".into(),
            value: "42".into(),
        });
        folder.entries.push(entry);
        root.groups.push(folder);

        write_kdbx4(&path, "master", &root).unwrap();

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
            Some("Passbolt Export")
        );
        assert_eq!(database.root.name, "root");
        let Some(Node::Group(folder)) = database.root.children.first() else {
            panic!("no folder group");
        };
        let Some(Node::Entry(entry)) = folder.children.first() else {
            panic!("no entry");
        };
        assert_eq!(entry.get_password(), Some("nested-password"));
        assert_eq!(entry.get("Account"), Some("42"));
        assert!(matches!(
            entry.fields.get("Account"),
            Some(Value::Protected(_))
        ));
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
