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
use zeroize::ZeroizeOnDrop;

use crate::Client;
use passbolt_sdk::resource::list::list_resources;
use passbolt_sdk::resource::view::ResourceView;
use passbolt_sdk::types::{Folder, TotpData};

/// Export Passbolt resources to a `KeePass` KDBX file, preserving folder hierarchy.
///
/// If `folder_id` is provided, only resources inside that folder subtree are exported.
/// The resources are listed as `list resource` lists them, their secrets decrypted by
/// `workers` threads (0 = one per CPU).
pub async fn export_keepass(
    client: &Client,
    output_path: &Path,
    password: &str,
    folder_id: Option<&str>,
    workers: usize,
) -> Result<()> {
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

    let progress = ProgressBar::new_spinner().with_message("Decrypting secrets...");
    progress.enable_steady_tick(std::time::Duration::from_millis(100));
    let views = list_resources(client, query, &[], Some(workers))
        .await
        .context("Failed to fetch resources")?;
    progress.finish_with_message("Secrets decrypted");

    let total = views.len();
    let (entries, failures) = collect_entries(&views);
    let exported = entries.len();

    write_kdbx(output_path, password, entries, &folders)?;

    println!("Exported {exported} entries to {}", output_path.display());

    // A partial backup must not look like a complete one to scripts: report and fail.
    ensure_no_decryption_failure(&failures, total)
}

/// The entries of the decrypted views, with their folder; the views that could not be
/// decrypted are skipped, their errors returned instead.
fn collect_entries(views: &[ResourceView]) -> (Vec<(Option<String>, KeePassEntry)>, Vec<String>) {
    let mut entries = Vec::with_capacity(views.len());
    let mut failures = Vec::new();
    for view in views {
        match &view.error {
            None => entries.push((view.folder_parent_id.clone(), build_entry(view))),
            Some(error) => failures.push(format!("Failed to decrypt '{}': {error}", view.name)),
        }
    }
    (entries, failures)
}

fn ensure_no_decryption_failure(failures: &[String], total: usize) -> Result<()> {
    if failures.is_empty() {
        return Ok(());
    }
    for failure in failures {
        eprintln!("Skipped: {failure}");
    }
    anyhow::bail!(
        "{} of {total} secrets could not be decrypted and were not exported",
        failures.len()
    )
}

// ─── Internal types ───────────────────────────────────────────────────────────

/// Intermediate plaintext representation; zeroized on drop so decrypted
/// passwords do not linger in the heap after the KDBX file is written.
#[derive(ZeroizeOnDrop)]
struct KeePassEntry {
    title: String,
    username: String,
    url: String,
    password: String,
    notes: String,
    otp: Option<String>,
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
        .map(|totp| build_otpauth(&view.name, &view.username, &totp));

    KeePassEntry {
        title: view.name.clone(),
        username: view.username.clone(),
        url: view.uri.clone(),
        password: view.password.clone().unwrap_or_default(),
        notes,
        otp,
    }
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
/// `KeePass` OTP plugin. The issuer defaults to the title, the account to the
/// username, then to the title.
fn build_otpauth(title: &str, username: &str, totp: &TotpData) -> String {
    let issuer = totp
        .issuer
        .as_deref()
        .filter(|issuer| !issuer.is_empty())
        .unwrap_or(title);
    let account = if username.is_empty() { title } else { username };
    let label = format!("{}:{}", percent_encode(issuer), percent_encode(account));
    let secret = percent_encode(&normalize_base32(totp.secret_key.as_deref().unwrap_or("")));
    let algorithm = percent_encode(&totp.algorithm.as_deref().unwrap_or("SHA1").to_uppercase());
    let digits = totp.digits.unwrap_or(6);
    let period = totp.period.unwrap_or(30);

    format!(
        "otpauth://totp/{label}?secret={secret}&issuer={}&algorithm={algorithm}&digits={digits}&period={period}",
        percent_encode(issuer)
    )
}

// ─── KDBX writer ─────────────────────────────────────────────────────────────

fn write_kdbx(
    path: &Path,
    password: &str,
    entries: Vec<(Option<String>, KeePassEntry)>,
    folders: &[Folder],
) -> Result<()> {
    use keepass::{
        config::DatabaseConfig,
        db::{Database, Group, Node},
        DatabaseKey,
    };

    let mut database = Database::new(DatabaseConfig::default());

    if folders.is_empty() {
        // No folder data — flat export
        for (_, entry) in entries {
            database
                .root
                .children
                .push(Node::Entry(build_kp_entry(entry)));
        }
    } else {
        // Build folder groups, preserving hierarchy.
        //
        // Algorithm:
        //  1. BFS-order folders (parents before children).
        //  2. Create a keepass Group for each folder.
        //  3. Add entries to the correct group (or root if no folder).
        //  4. Assemble in reverse-BFS order: remove deepest groups first and
        //     attach them to their parent groups, ending with root-level groups
        //     attached to database.root.

        // Step 1: BFS ordering
        let bfs_order = bfs_folders(folders);

        // Step 2: create one Group per folder_id
        let mut groups: HashMap<String, Group> = bfs_order
            .iter()
            .map(|folder| {
                (
                    folder.id.clone(),
                    Group {
                        name: folder.name.clone(),
                        ..Default::default()
                    },
                )
            })
            .collect();

        // Step 3: add entries to the correct group (or database.root)
        for (folder_id, entry) in entries {
            let node = Node::Entry(build_kp_entry(entry));
            match folder_id.as_deref().and_then(|id| groups.get_mut(id)) {
                Some(group) => group.children.push(node),
                None => database.root.children.push(node),
            }
        }

        // Step 4: assemble tree in reverse-BFS order (deepest first)
        for folder in bfs_order.iter().rev() {
            if let Some(group) = groups.remove(&folder.id) {
                let node = Node::Group(group);
                match folder
                    .folder_parent_id
                    .as_deref()
                    .and_then(|parent_id| groups.get_mut(parent_id))
                {
                    Some(parent) => parent.children.push(node),
                    None => database.root.children.push(node),
                }
            }
        }
    }

    let key = DatabaseKey::new().with_password(password);
    save_replacing(path, |file| {
        database
            .save(file, key)
            .with_context(|| format!("Cannot write KDBX to {}", path.display()))
    })
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

/// Build a keepass `Entry` from our intermediate representation.
///
/// Uses `std::mem::take` to move each field out without triggering borrow
/// conflicts with the `Drop` impl added by `ZeroizeOnDrop`.  After all takes,
/// `source` holds only empty/None values and is then zeroized on drop.
fn build_kp_entry(mut source: KeePassEntry) -> keepass::db::Entry {
    use keepass::db::{Entry, Value};
    use std::mem::take;

    let mut entry = Entry::new();
    entry
        .fields
        .insert("Title".into(), Value::Unprotected(take(&mut source.title)));
    entry.fields.insert(
        "UserName".into(),
        Value::Unprotected(take(&mut source.username)),
    );
    entry
        .fields
        .insert("URL".into(), Value::Unprotected(take(&mut source.url)));
    entry.fields.insert(
        "Password".into(),
        Value::Protected(SecStr::new(take(&mut source.password).into_bytes())),
    );
    entry
        .fields
        .insert("Notes".into(), Value::Unprotected(take(&mut source.notes)));

    if let Some(otp) = take(&mut source.otp) {
        entry.fields.insert(
            "otp".into(),
            Value::Protected(SecStr::new(otp.into_bytes())),
        );
    }

    entry
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
    use passbolt_sdk::types::{Resource, ResourceType};
    use rstest::rstest;

    fn make_resource(name: &str) -> Resource {
        Resource {
            id: "test-id".into(),
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

    fn make_totp(secret: &str, issuer: Option<&str>) -> TotpData {
        TotpData {
            secret_key: Some(secret.into()),
            algorithm: Some("SHA1".into()),
            digits: Some(6),
            period: Some(30),
            issuer: issuer.map(Into::into),
        }
    }

    fn make_entry(title: &str, otp: Option<&str>) -> KeePassEntry {
        KeePassEntry {
            title: title.into(),
            username: String::new(),
            url: String::new(),
            password: format!("{title}-password"),
            notes: String::new(),
            otp: otp.map(Into::into),
        }
    }

    fn folder_ids<'a>(folders: &[&'a Folder]) -> Vec<&'a str> {
        folders.iter().map(|folder| folder.id.as_str()).collect()
    }

    fn child_group<'a>(group: &'a keepass::db::Group, name: &str) -> &'a keepass::db::Group {
        group
            .children
            .iter()
            .find_map(|node| match node {
                Node::Group(child) if child.name == name => Some(child),
                _ => None,
            })
            .unwrap()
    }

    fn child_entries(group: &keepass::db::Group) -> Vec<&keepass::db::Entry> {
        group
            .children
            .iter()
            .filter_map(|node| match node {
                Node::Entry(entry) => Some(entry),
                Node::Group(_) => None,
            })
            .collect()
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
    #[case::plain(
        "MyService",
        "alice",
        make_totp("JBSWY3DPEHPK3PXP", Some("MyIssuer")),
        "otpauth://totp/MyIssuer:alice?secret=JBSWY3DPEHPK3PXP&issuer=MyIssuer&algorithm=SHA1&digits=6&period=30"
    )]
    #[case::special_characters(
        "Title",
        "me&you?#a:b/c",
        make_totp("jbswy3d=", Some("A&B?C#D:E/F G")),
        "otpauth://totp/A%26B%3FC%23D%3AE%2FF%20G:me%26you%3F%23a%3Ab%2Fc?secret=JBSWY3D&issuer=A%26B%3FC%23D%3AE%2FF%20G&algorithm=SHA1&digits=6&period=30"
    )]
    #[case::defaults(
        "My Service",
        "",
        TotpData { secret_key: Some("JBSWY3DP".into()), algorithm: None, digits: None, period: None, issuer: None },
        "otpauth://totp/My%20Service:My%20Service?secret=JBSWY3DP&issuer=My%20Service&algorithm=SHA1&digits=6&period=30"
    )]
    #[case::empty_issuer_falls_back_to_title(
        "Fallback",
        "bob",
        make_totp("JBSWY3DP", Some("")),
        "otpauth://totp/Fallback:bob?secret=JBSWY3DP&issuer=Fallback&algorithm=SHA1&digits=6&period=30"
    )]
    fn test_build_otpauth(
        #[case] title: &str,
        #[case] username: &str,
        #[case] totp: TotpData,
        #[case] expected: &str,
    ) {
        assert_eq!(build_otpauth(title, username, &totp), expected);
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
    fn test_write_kdbx_keeps_hierarchy_of_exported_subtree() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("export.kdbx");
        let folders = vec![
            make_folder("child", Some("sub")),
            make_folder("sub", Some("outside")),
        ];
        let entries = vec![
            (None, make_entry("at-root", None)),
            (
                Some("child".to_owned()),
                make_entry("nested", Some("otpauth://totp/Issuer:me?secret=JBSWY3DP")),
            ),
        ];

        write_kdbx(&path, "master", entries, &folders).unwrap();

        let mut file = std::fs::File::open(&path).unwrap();
        let database =
            Database::open(&mut file, DatabaseKey::new().with_password("master")).unwrap();
        let root_entries = child_entries(&database.root);
        assert_eq!(root_entries.len(), 1);
        assert_eq!(root_entries[0].get_title(), Some("at-root"));
        assert_eq!(root_entries[0].get_password(), Some("at-root-password"));
        let sub = child_group(&database.root, "sub-name");
        let child = child_group(sub, "child-name");
        let nested = child_entries(child);
        assert_eq!(nested[0].get_title(), Some("nested"));
        assert!(matches!(
            nested[0].fields.get("otp"),
            Some(Value::Protected(_))
        ));
        assert_eq!(
            nested[0].get("otp"),
            Some("otpauth://totp/Issuer:me?secret=JBSWY3DP")
        );
    }

    fn types() -> Vec<ResourceType> {
        ["password-string", "password-and-description", "v5-default"]
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
    fn test_collect_entries_skips_and_counts_decryption_failures() {
        let broken = ResourceView::new(make_resource("broken"), None, &types())
            .unwrap()
            .with_error(&passbolt_sdk::PassboltError::Other("no key".into()));
        let views = vec![view_of(make_resource("decrypted"), "secret"), broken];

        let (entries, failures) = collect_entries(&views);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1.title, "decrypted");
        assert_eq!(failures, ["Failed to decrypt 'broken': no key"]);
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

    #[test]
    fn test_ensure_no_decryption_failure_reports_count() {
        let failures = vec!["Failed to decrypt 'broken'".to_string()];

        let error = ensure_no_decryption_failure(&failures, 3).unwrap_err();

        assert_eq!(
            error.to_string(),
            "1 of 3 secrets could not be decrypted and were not exported"
        );
    }

    #[test]
    fn test_ensure_no_decryption_failure_accepts_complete_export() {
        assert!(ensure_no_decryption_failure(&[], 3).is_ok());
    }
}
