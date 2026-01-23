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

//! Output formats and the less used flags: `--json` on writes, columns, tables, updates.

use keepass::db::NodeRef;
use keepass::{Database, DatabaseKey};
use predicates::str::contains;
use serde_json::json;

use crate::common::{
    admin_id, create_folder, create_group, create_resource, passbolt, run, run_json, run_text,
    unique_name, Cleanup, UNKNOWN_ID,
};

const TOTP_KEY: &str = "JBSWY3DPEHPK3PXP";

fn get(id: &str) -> serde_json::Value {
    run_json(&["get", "resource", "--id", id])
}

#[test]
fn writes_report_their_result_in_json() {
    let folder = create_folder(&unique_name("json"), &[]);
    let resource = create_resource(&unique_name("json"), "p", &[]);

    let moved = run_json(&[
        "move",
        "resource",
        "--id",
        &resource.id,
        "--folder-parent-id",
        &folder.id,
    ]);
    let shared = run_json(&[
        "share",
        "resource",
        "--id",
        &resource.id,
        "--user",
        &admin_id(),
    ]);
    let deleted = run_json(&["delete", "resource", "--id", &resource.id]);

    assert_eq!(moved, json!({"id": resource.id, "result": "moved"}));
    assert_eq!(shared, json!({"id": resource.id, "result": "shared"}));
    assert_eq!(deleted, json!({"id": resource.id, "result": "deleted"}));
}

#[test]
fn deleting_an_unknown_resource_fails() {
    passbolt()
        .args(["delete", "resource", "--id", UNKNOWN_ID])
        .assert()
        .failure()
        .stderr(contains("404"));
}

#[test]
fn update_changes_the_username_note_pin_and_secret_fields() {
    let resource = create_resource(&unique_name("update"), "p", &["--type", "v5-default"]);
    let pin = Cleanup::new(
        "resource",
        &run_json(&[
            "create",
            "resource",
            "--type",
            "v5-pin-code",
            "--name",
            &unique_name("pin"),
            "--pin-code",
            "1234",
        ]),
    );

    run(&[
        "update",
        "resource",
        "--id",
        &resource.id,
        "--username",
        "renamed",
        "--note",
        "secret note",
        "--secret-field",
        "password=from-field",
    ]);
    run(&[
        "update",
        "resource",
        "--id",
        &pin.id,
        "--pin-code",
        "987654",
    ]);

    let updated = get(&resource.id);
    assert_eq!(updated["username"], "renamed");
    assert_eq!(updated["secret"]["description"], "secret note");
    assert_eq!(updated["password"], "from-field");
    assert_eq!(get(&pin.id)["secret"]["pin_code"], "987654");
}

#[test]
fn update_replaces_the_totp_settings() {
    let resource = create_resource(&unique_name("totp"), "p", &["--totp-key", TOTP_KEY]);

    run(&[
        "update",
        "resource",
        "--id",
        &resource.id,
        "--totp-key",
        "GEZDGNBVGY3TQOJQ",
        "--totp-algo",
        "SHA256",
        "--totp-period",
        "60",
    ]);

    let totp = &get(&resource.id)["secret"]["totp"];
    assert_eq!(totp["secret_key"], "GEZDGNBVGY3TQOJQ");
    assert_eq!(totp["algorithm"], "SHA256");
    assert_eq!(totp["period"], 60);
}

#[test]
fn user_group_and_folder_lists_take_columns_and_refuse_unknown_ones() {
    let folder = create_folder(&unique_name("columns"), &[]);
    let group = create_group(&unique_name("columns"), &admin_id(), &[]);

    let users = run_json(&["list", "user", "-c", "Username", "-c", "First Name"]);
    let folders = run_json(&["list", "folder", "-c", "ID", "-c", "FolderParentID"]);
    let groups = run_json(&["list", "group", "-c", "Name", "-c", "UserCount"]);

    let user = users.as_array().unwrap().first().unwrap();
    assert!(
        user["username"].is_string() && user["first_name"].is_string(),
        "{user}"
    );
    assert!(folders
        .as_array()
        .unwrap()
        .iter()
        .any(|listed| listed == &json!({"id": folder.id, "folder_parent_id": null})));
    assert!(groups
        .as_array()
        .unwrap()
        .iter()
        .any(|listed| listed["name"].is_string() && listed["members"].is_number()));
    for entity in ["user", "group", "folder"] {
        passbolt()
            .args(["list", entity, "-c", "colour"])
            .assert()
            .failure()
            .stderr(contains("Unknown column colour"));
    }
    drop(group);
}

#[test]
fn folder_and_totp_show_as_tables() {
    let folder = create_folder(&unique_name("table"), &[]);
    let resource = create_resource(&unique_name("table"), "p", &["--totp-key", TOTP_KEY]);

    let folder_table = run_text(&["get", "folder", "--id", &folder.id]);
    let totp_text = run_text(&["get", "totp", "--id", &resource.id]);

    assert!(folder_table.contains(&folder.id), "{folder_table}");
    assert!(totp_text.contains("s remaining"), "{totp_text}");
}

#[test]
fn a_folder_moves_back_to_the_root_with_an_empty_parent() {
    let parent = create_folder(&unique_name("parent"), &[]);
    let child = create_folder(&unique_name("child"), &["--folder-parent-id", &parent.id]);

    run(&[
        "move",
        "folder",
        "--id",
        &child.id,
        "--folder-parent-id",
        "",
    ]);

    let moved = run_json(&["get", "folder", "--id", &child.id]);
    assert_eq!(moved["folder_parent_id"], serde_json::Value::Null);
}

#[test]
fn a_full_keepass_export_contains_the_user_resources() {
    let name = unique_name("full-export");
    let _resource = create_resource(&name, "full-export-password", &["--type", "v5-default"]);
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("export.kdbx");

    run(&[
        "export",
        "keepass",
        "--output",
        file.to_str().unwrap(),
        "--password",
        "kdbx-password",
    ]);

    let database = Database::open(
        &mut std::fs::File::open(&file).unwrap(),
        DatabaseKey::new().with_password("kdbx-password"),
    )
    .unwrap();
    let exported = database.root.iter().any(|node| {
        matches!(node, NodeRef::Entry(entry)
            if entry.get_title() == Some(name.as_str()) && entry.get_password() == Some("full-export-password"))
    });
    assert!(exported, "{name} missing from the export");
}
