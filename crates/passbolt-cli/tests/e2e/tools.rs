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

//! `exec`, `export keepass` and `verify`.

use keepass::db::NodeRef;
use keepass::{Database, DatabaseKey};
use predicates::str::contains;

use crate::common::{
    create_folder, create_resource, passbolt, run, run_json, share_with_user_id, unique_name,
    Cleanup,
};

#[test]
fn exec_injects_the_password_into_the_environment() {
    let resource = create_resource(&unique_name("exec"), "exec-password", &[]);

    passbolt()
        .env("E2E_SECRET", format!("passbolt://{}", resource.id))
        .args(["exec", "--", "/bin/sh", "-c", "printf %s \"$E2E_SECRET\""])
        .assert()
        .success()
        .stdout("exec-password");
}

#[test]
fn exec_gives_an_empty_value_for_a_resource_without_a_password() {
    let resource = Cleanup::new(
        "resource",
        &run_json(&[
            "create",
            "resource",
            "--type",
            "v5-note",
            "--name",
            &unique_name("exec-note"),
            "--note",
            "not a password",
        ]),
    );

    passbolt()
        .env("E2E_SECRET", format!("passbolt://{}", resource.id))
        .args(["exec", "--", "/bin/sh", "-c", "printf \"[$E2E_SECRET]\""])
        .assert()
        .success()
        .stdout("[]");
}

#[test]
fn exec_with_debug_names_each_variable_it_fills() {
    let resource = create_resource(&unique_name("exec-debug"), "debug-password", &[]);

    passbolt()
        .env("E2E_SECRET", format!("passbolt://{}", resource.id))
        .args(["--debug", "exec", "--", "/bin/sh", "-c", "printf ran"])
        .assert()
        .success()
        .stdout(format!(
            "E2E_SECRET env var populated with resource id {}\nran",
            resource.id
        ));
}

#[test]
fn keepass_export_contains_the_folder_resources() {
    let folder = create_folder(&unique_name("export"), &[]);
    let name = unique_name("exported");
    let _resource = create_resource(
        &name,
        "exported-password",
        &["--folder-parent-id", &folder.id],
    );
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("export.kdbx");

    run(&[
        "export",
        "keepass",
        "--output",
        file.to_str().unwrap(),
        "--password",
        "kdbx-password",
        "--folder-id",
        &folder.id,
    ]);

    let database = Database::open(
        &mut std::fs::File::open(&file).unwrap(),
        DatabaseKey::new().with_password("kdbx-password"),
    )
    .unwrap();
    let exported = database.root.iter().any(|node| {
        matches!(node, NodeRef::Entry(entry)
            if entry.get_title() == Some(name.as_str()) && entry.get_password() == Some("exported-password"))
    });
    assert!(exported, "{name} missing from the export");
}

#[test]
fn keepass_export_contains_shared_v5_resources() {
    let folder = create_folder(&unique_name("export-shared"), &[]);
    let name = unique_name("exported-shared");
    let _resource = create_resource(
        &name,
        "shared-password",
        &["--type", "v5-default", "--folder-parent-id", &folder.id],
    );
    run(&[
        "share",
        "folder",
        "--id",
        &folder.id,
        "-u",
        &share_with_user_id(),
        "-t",
        "1",
        "--with-content",
    ]);
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("export.kdbx");

    run(&[
        "export",
        "keepass",
        "-f",
        file.to_str().unwrap(),
        "-p",
        "kdbx-password",
        "--folder-id",
        &folder.id,
    ]);

    let database = Database::open(
        &mut std::fs::File::open(&file).unwrap(),
        DatabaseKey::new().with_password("kdbx-password"),
    )
    .unwrap();
    let exported = database.root.iter().any(|node| {
        matches!(node, NodeRef::Entry(entry)
            if entry.get_title() == Some(name.as_str()) && entry.get_password() == Some("shared-password"))
    });
    assert!(exported, "{name} missing from the export");
}

#[test]
fn writes_still_work_after_verify() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.toml");
    passbolt()
        .env("PASSBOLT_CONFIG", &config)
        .arg("verify")
        .assert()
        .success()
        .stdout(contains("Verification Enabled"));

    // The pre-login verify request is the one receiving the CSRF cookie.
    let output = passbolt()
        .env("PASSBOLT_CONFIG", &config)
        .args([
            "create",
            "folder",
            "--name",
            &unique_name("verified"),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let _folder = Cleanup::new("folder", &serde_json::from_slice(&output).unwrap());
}

#[test]
fn verify_pins_the_server_key_and_saves_nothing_else() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.toml");

    // The credentials come from the environment, as overrides of the empty config file.
    passbolt()
        .env("PASSBOLT_CONFIG", &config)
        .arg("verify")
        .assert()
        .success();

    let saved = std::fs::read_to_string(&config).unwrap();
    assert!(
        saved.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----"),
        "{saved}"
    );
    for variable in [
        "PASSBOLT_E2E_USER_PASSWORD",
        "PASSBOLT_E2E_USER_PRIVATE_KEY_FILE",
    ] {
        let override_value = std::env::var(variable).unwrap();
        assert!(
            !saved.contains(&override_value),
            "{variable} saved in the config file"
        );
    }
}

#[test]
fn keepass_export_refuses_an_empty_master_password() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("export.kdbx");

    // As go-passbolt-cli, an empty --password prompts; the empty answer is refused.
    passbolt()
        .args(["export", "keepass", "-f", file.to_str().unwrap(), "-p", ""])
        .write_stdin("\n")
        .assert()
        .failure()
        .stderr(contains("Empty password"));

    assert!(!file.exists());
}

#[test]
fn a_missing_password_outside_a_terminal_creates_no_resource() {
    let name = unique_name("missing");

    // As go-passbolt-cli: no prompt for the resource password when stdin is not a terminal.
    passbolt()
        .args(["create", "resource", "--name", &name])
        .write_stdin("piped\n")
        .assert()
        .failure()
        .stderr(contains("required flag \"password\" not set"));

    assert_eq!(
        run_json(&["list", "resource", "--search", &name]),
        serde_json::json!([])
    );
}
