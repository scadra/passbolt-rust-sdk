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

//! Folder permissions reaching the content as the browser extension spreads them: sharing a
//! folder with its content, moving with the folder permissions, creating in a shared folder.

use serde_json::Value;

use crate::common::{
    admin_id, create_folder, create_resource, current_user_id, passbolt_as, run, run_json,
    share_with_user_id, unique_name, Account, Cleanup, ADMIN,
};

const READ: i64 = 1;
const UPDATE: i64 = 7;

fn permission_of(permissions: &Value, user_id: &str) -> Option<i64> {
    permissions
        .as_array()
        .unwrap()
        .iter()
        .find(|permission| permission["aro_foreign_key"] == user_id)
        .and_then(|permission| permission["type"].as_i64())
}

fn on_resource(resource: &Cleanup, user_id: &str) -> Option<i64> {
    let permissions = run_json(&["get", "resource-permissions", "--id", &resource.id]);
    permission_of(&permissions, user_id)
}

fn on_folder(folder: &Cleanup, user_id: &str) -> Option<i64> {
    let permissions = run_json(&["get", "folder-permissions", "--id", &folder.id]);
    permission_of(&permissions, user_id)
}

fn resource_in(folder: &Cleanup) -> Cleanup {
    create_resource(
        &unique_name("content"),
        "p",
        &["--type", "v5-default", "--folder-parent-id", &folder.id],
    )
}

fn share_folder(folder: &Cleanup, user_id: &str, permission_type: &str) {
    run(&[
        "share",
        "folder",
        "--id",
        &folder.id,
        "--user",
        user_id,
        "--type",
        permission_type,
        "--with-content",
    ]);
}

fn share_resource(resource: &Cleanup, user_id: &str, permission_type: &str) {
    run(&[
        "share",
        "resource",
        "--id",
        &resource.id,
        "--user",
        user_id,
        "--type",
        permission_type,
    ]);
}

#[test]
fn a_new_grant_reaches_the_sub_folders_and_their_resources() {
    let recipient = share_with_user_id();
    let folder = create_folder(&unique_name("shared"), &[]);
    let sub_folder = create_folder(&unique_name("sub"), &["--folder-parent-id", &folder.id]);
    let resource = resource_in(&sub_folder);

    share_folder(&folder, &recipient, "1");

    assert_eq!(on_folder(&sub_folder, &recipient), Some(READ));
    assert_eq!(on_resource(&resource, &recipient), Some(READ));
}

#[test]
fn raising_an_access_only_reaches_the_content_the_user_has() {
    let recipient = share_with_user_id();
    let folder = create_folder(&unique_name("shared"), &[]);
    let shared = resource_in(&folder);
    let kept_private = resource_in(&folder);
    share_folder(&folder, &recipient, "1");
    share_resource(&kept_private, &recipient, "-1");

    share_folder(&folder, &recipient, "7");

    assert_eq!(on_resource(&shared, &recipient), Some(UPDATE));
    assert_eq!(on_resource(&kept_private, &recipient), None);
}

#[test]
fn revoking_on_the_folder_removes_the_access_from_the_content() {
    let recipient = share_with_user_id();
    let folder = create_folder(&unique_name("shared"), &[]);
    let resource = resource_in(&folder);
    share_folder(&folder, &recipient, "1");

    share_folder(&folder, &recipient, "-1");

    assert_eq!(on_folder(&folder, &recipient), None);
    assert_eq!(on_resource(&resource, &recipient), None);
}

#[test]
fn sharing_a_folder_again_as_it_is_leaves_the_content_alone() {
    let recipient = share_with_user_id();
    let folder = create_folder(&unique_name("shared"), &[]);
    let resource = resource_in(&folder);
    share_folder(&folder, &recipient, "1");
    share_resource(&resource, &recipient, "7");

    share_folder(&folder, &recipient, "1");

    assert_eq!(on_resource(&resource, &recipient), Some(UPDATE));
}

const OWNER: i64 = 15;

fn move_with_permissions(entity: &str, item: &Cleanup, destination: &str) {
    run(&[
        "move",
        entity,
        "--id",
        &item.id,
        "--folder-parent-id",
        destination,
        "--with-folder-permissions",
    ]);
}

fn parent_of(entity: &str, item: &Cleanup) -> Value {
    run_json(&["get", entity, "--id", &item.id])["folder_parent_id"].clone()
}

#[test]
fn moving_out_of_a_shared_folder_drops_what_it_gave() {
    let recipient = share_with_user_id();
    let me = current_user_id(Account::User);
    let folder = create_folder(&unique_name("shared"), &[]);
    let resource = resource_in(&folder);
    share_folder(&folder, &recipient, "1");

    move_with_permissions("resource", &resource, "");

    assert_eq!(parent_of("resource", &resource), Value::Null);
    assert_eq!(on_resource(&resource, &recipient), None);
    assert_eq!(on_resource(&resource, &me), Some(OWNER));
}

#[test]
fn moving_between_folders_trades_the_old_permissions_for_the_new() {
    let recipient = share_with_user_id();
    let admin = admin_id();
    let from = create_folder(&unique_name("from"), &[]);
    let to = create_folder(&unique_name("to"), &[]);
    let resource = resource_in(&from);
    share_folder(&from, &recipient, "1");
    share_folder(&to, &admin, "7");

    move_with_permissions("resource", &resource, &to.id);

    assert_eq!(on_resource(&resource, &recipient), None);
    assert_eq!(on_resource(&resource, &admin), Some(UPDATE));
}

#[test]
fn an_access_not_given_by_the_old_folder_stays() {
    let recipient = share_with_user_id();
    let admin = admin_id();
    let folder = create_folder(&unique_name("shared"), &[]);
    let resource = resource_in(&folder);
    share_folder(&folder, &recipient, "1");
    share_resource(&resource, &admin, "7");

    move_with_permissions("resource", &resource, "");

    assert_eq!(on_resource(&resource, &admin), Some(UPDATE));
    assert_eq!(on_resource(&resource, &recipient), None);
}

#[test]
fn moving_never_lowers_an_access() {
    let recipient = share_with_user_id();
    let folder = create_folder(&unique_name("read-only"), &[]);
    share_folder(&folder, &recipient, "1");
    let resource = create_resource(&unique_name("outside"), "p", &["--type", "v5-default"]);
    share_resource(&resource, &recipient, "7");

    move_with_permissions("resource", &resource, &folder.id);

    assert_eq!(on_resource(&resource, &recipient), Some(UPDATE));
}

#[test]
fn only_an_owner_moves_with_the_permissions_and_nothing_moves_otherwise() {
    let admin = admin_id();
    let folder = create_folder(&unique_name("shared"), &[]);
    share_folder(&folder, &admin, "7");
    let resource = create_resource(&unique_name("updatable"), "p", &["--type", "v5-default"]);
    share_resource(&resource, &admin, "7");

    passbolt_as(ADMIN)
        .args([
            "move",
            "resource",
            "--id",
            &resource.id,
            "--folder-parent-id",
            &folder.id,
        ])
        .arg("--with-folder-permissions")
        .assert()
        .failure()
        .stderr(predicates::str::contains("Only an owner"));

    assert_eq!(parent_of("resource", &resource), Value::Null);
}

#[test]
fn moving_a_folder_with_its_permissions_reaches_its_content() {
    let recipient = share_with_user_id();
    let shared = create_folder(&unique_name("shared"), &[]);
    share_folder(&shared, &recipient, "1");
    let moved = create_folder(&unique_name("moved"), &[]);
    let resource = resource_in(&moved);

    move_with_permissions("folder", &moved, &shared.id);

    assert_eq!(parent_of("folder", &moved), shared.id.as_str());
    assert_eq!(on_folder(&moved, &recipient), Some(READ));
    assert_eq!(on_resource(&resource, &recipient), Some(READ));
}

#[test]
fn a_resource_created_in_a_shared_folder_gets_its_permissions() {
    let recipient = share_with_user_id();
    let admin = admin_id();
    let folder = create_folder(&unique_name("shared"), &[]);
    share_folder(&folder, &recipient, "1");
    share_folder(&folder, &admin, "7");

    let resource = create_resource(
        &unique_name("inherits"),
        "inherited-password",
        &["--type", "v5-default", "--folder-parent-id", &folder.id],
    );

    assert_eq!(on_resource(&resource, &recipient), Some(READ));
    assert_eq!(on_resource(&resource, &admin), Some(UPDATE));
    let as_admin = crate::common::run_json_as(ADMIN, &["get", "resource", "--id", &resource.id]);
    assert_eq!(as_admin["password"], "inherited-password");
    assert_eq!(as_admin["metadata_key_type"], "shared_key");
}

#[test]
fn a_folder_created_in_a_shared_folder_gets_its_permissions() {
    let recipient = share_with_user_id();
    let folder = create_folder(&unique_name("shared"), &[]);
    share_folder(&folder, &recipient, "7");

    let sub_folder = create_folder(
        &unique_name("inherits"),
        &["--folder-parent-id", &folder.id],
    );

    assert_eq!(on_folder(&sub_folder, &recipient), Some(UPDATE));
}

#[test]
fn a_resource_created_in_a_personal_folder_stays_personal() {
    let folder = create_folder(&unique_name("personal"), &[]);

    let resource = resource_in(&folder);

    let fetched = run_json(&["get", "resource", "--id", &resource.id]);
    assert_eq!(fetched["metadata_key_type"], "user_key");
    let permissions = run_json(&["get", "resource-permissions", "--id", &resource.id]);
    assert_eq!(permissions.as_array().unwrap().len(), 1);
}
