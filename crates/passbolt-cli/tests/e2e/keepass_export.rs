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

//! `export keepass` run with go-passbolt-cli's command lines, the files read back.

use std::path::Path;

use keepass::config::{DatabaseVersion, InnerCipherConfig, KdfConfig};
use keepass::db::{Entry, Group, Node, Value};
use keepass::{Database, DatabaseKey};
use predicates::str::contains;

use crate::common::{create_folder, create_resource, passbolt, unique_name, Cleanup};

const TOTP_KEY: &str = "JBSWY3DPEHPK3PXP";
const CUSTOM_FIELD_ID: &str = "0f7b6a51-0000-4000-8000-0000000000e1";
const URI: &str = "https://keepass.e2e.test/login";

/// A folder holding a v5 resource with a URI, a TOTP and a custom field.
struct Exported {
    folder_name: String,
    resource_name: String,
    _resource: Cleanup,
    _folder: Cleanup,
}

fn create_exported() -> Exported {
    let folder_name = unique_name("keepass-folder");
    let folder = create_folder(&folder_name, &[]);
    let resource_name = unique_name("keepass");
    let custom_fields = format!(
        r#"custom_fields=[{{"id":"{CUSTOM_FIELD_ID}","type":"text","metadata_key":"Account"}}]"#
    );
    let secret_custom_fields = format!(
        r#"custom_fields=[{{"id":"{CUSTOM_FIELD_ID}","type":"text","secret_value":"42"}}]"#
    );
    let resource = create_resource(
        &resource_name,
        "keepass-password",
        &[
            "--type",
            "v5-default-with-totp",
            "--username",
            "alice",
            "--uri",
            URI,
            "--totp-key",
            TOTP_KEY,
            "--field",
            &custom_fields,
            "--secret-field",
            &secret_custom_fields,
            "--folder-parent-id",
            &folder.id,
        ],
    );
    Exported {
        folder_name,
        resource_name,
        _resource: resource,
        _folder: folder,
    }
}

/// `passbolt export keepass <arguments>`, which must succeed as go-passbolt-cli's does.
/// A full export decrypts the whole vault, which outgrows the one-minute default of
/// `--timeout` on the test server: a user with a large vault raises it the same way.
fn export(arguments: &[&str]) -> String {
    let output = passbolt()
        .args(["--timeout", "10m", "export", "keepass"])
        .args(arguments)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    String::from_utf8(output).unwrap()
}

fn open(file: &Path, password: &str) -> Database {
    Database::open(
        &mut std::fs::File::open(file).unwrap(),
        DatabaseKey::new().with_password(password),
    )
    .unwrap()
}

fn child_group<'a>(group: &'a Group, name: &str) -> Option<&'a Group> {
    group.children.iter().find_map(|node| match node {
        Node::Group(child) if child.name == name => Some(child),
        _ => None,
    })
}

fn child_entry<'a>(group: &'a Group, title: &str) -> Option<&'a Entry> {
    group.children.iter().find_map(|node| match node {
        Node::Entry(entry) if entry.get_title() == Some(title) => Some(entry),
        _ => None,
    })
}

/// The exported resource, in the group of its folder inside `root`.
fn exported_entry<'a>(database: &'a Database, exported: &Exported) -> &'a Entry {
    assert_eq!(database.root.name, "root");
    let folder = child_group(&database.root, &exported.folder_name)
        .unwrap_or_else(|| panic!("no group {}", exported.folder_name));
    child_entry(folder, &exported.resource_name)
        .unwrap_or_else(|| panic!("no entry {}", exported.resource_name))
}

fn assert_protected(entry: &Entry, key: &str) {
    assert!(
        matches!(entry.fields.get(key), Some(Value::Protected(_))),
        "{key} is not protected"
    );
}

fn assert_resource_exported(database: &Database, exported: &Exported) {
    assert_eq!(
        database.meta.database_name.as_deref(),
        Some("Passbolt Export")
    );
    let entry = exported_entry(database, exported);
    assert_eq!(entry.get_username(), Some("alice"));
    assert_eq!(entry.get_url(), Some(URI));
    assert_eq!(entry.get_password(), Some("keepass-password"));
    assert_eq!(entry.get("Account"), Some("42"));
    let otp = entry.get("otp").unwrap();
    assert!(
        otp.starts_with("otpauth://totp/https%3A%2F%2Fkeepass.e2e.test%2Flogin:alice?"),
        "{otp}"
    );
    assert!(otp.contains(&format!("secret={TOTP_KEY}")), "{otp}");
    assert!(
        otp.contains("issuer=https%3A%2F%2Fkeepass.e2e.test%2Flogin"),
        "{otp}"
    );
    for key in ["Password", "otp", "Account"] {
        assert_protected(entry, key);
    }
}

#[test]
fn keepass_export_writes_kdbx_3_1_by_default() {
    let exported = create_exported();
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("x.kdbx");

    let stdout = export(&["-f", file.to_str().unwrap(), "-p", "pw"]);

    assert!(stdout.starts_with("Getting Resources...\n"), "{stdout}");
    assert!(stdout.ends_with("Done\n"), "{stdout}");
    let database = open(&file, "pw");
    assert_eq!(database.config.version, DatabaseVersion::KDB3(1));
    assert_eq!(
        database.config.inner_cipher_config,
        InnerCipherConfig::Salsa20
    );
    assert!(matches!(database.config.kdf_config, KdfConfig::Aes { .. }));
    assert_resource_exported(&database, &exported);
}

#[test]
fn keepass_export_writes_kdbx_4_on_request() {
    let exported = create_exported();
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("x.kdbx");

    let stdout = export(&[
        "-f",
        file.to_str().unwrap(),
        "-p",
        "pw",
        "--kdbx-version",
        "v4",
    ]);

    assert!(stdout.ends_with("Done\n"), "{stdout}");
    let database = open(&file, "pw");
    assert!(matches!(database.config.version, DatabaseVersion::KDB4(_)));
    assert!(matches!(
        database.config.kdf_config,
        KdfConfig::Argon2 { .. }
    ));
    assert_resource_exported(&database, &exported);
}

#[test]
fn keepass_export_refuses_an_unknown_kdbx_version() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("x.kdbx");

    passbolt()
        .args([
            "export",
            "keepass",
            "-f",
            file.to_str().unwrap(),
            "-p",
            "pw",
        ])
        .args(["--kdbx-version", "v5"])
        .assert()
        .failure()
        .stderr(contains(r#"invalid kdbx-version "v5": must be v3 or v4"#));

    assert!(!file.exists());
}

#[test]
fn keepass_export_reads_a_missing_password_from_stdin() {
    let exported = create_exported();
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("x.kdbx");

    passbolt()
        .args([
            "--timeout",
            "10m",
            "export",
            "keepass",
            "-f",
            file.to_str().unwrap(),
        ])
        .write_stdin("piped-password\n")
        .assert()
        .success();

    assert_resource_exported(&open(&file, "piped-password"), &exported);
}

#[test]
fn keepass_export_writes_passbolt_export_kdbx_by_default() {
    let directory = tempfile::tempdir().unwrap();
    let folder = create_folder(&unique_name("keepass-default-file"), &[]);

    passbolt()
        .current_dir(directory.path())
        .args(["export", "keepass", "-p", "pw", "--folder-id", &folder.id])
        .assert()
        .success();

    let database = open(&directory.path().join("passbolt-export.kdbx"), "pw");
    assert_eq!(database.config.version, DatabaseVersion::KDB3(1));
}
