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

//! What sharing refuses before touching anything, group managers kept, folder deletion.

use predicates::str::contains;
use serde_json::Value;

use crate::common::{
    admin_id, assert_not_found, create_folder, create_group, create_resource, current_user_id,
    passbolt, passbolt_as, run, run_json, run_json_as, share_with_user_id, unique_name, Account,
    ADMIN,
};

fn share(args: &[&str]) -> assert_cmd::assert::Assert {
    passbolt().arg("share").args(args).assert()
}

#[test]
fn an_unknown_permission_type_is_refused() {
    let resource = create_resource(&unique_name("typed"), "p", &[]);

    share(&[
        "resource",
        "--id",
        &resource.id,
        "-u",
        &share_with_user_id(),
        "-t",
        "3",
    ])
    .failure()
    .stderr(contains("not a permission type"));
}

#[test]
fn sharing_with_nobody_is_refused() {
    let resource = create_resource(&unique_name("nobody"), "p", &[]);

    share(&["resource", "--id", &resource.id, "-t", "7"]).failure();
}

#[test]
fn revoking_someone_without_access_changes_nothing_for_the_others() {
    let recipient = share_with_user_id();
    let resource = create_resource(&unique_name("revoke"), "p", &["--type", "v5-default"]);
    run(&[
        "share",
        "resource",
        "--id",
        &resource.id,
        "-u",
        &recipient,
        "-t",
        "1",
    ]);

    share(&[
        "resource",
        "--id",
        &resource.id,
        "-u",
        &recipient,
        "-u",
        &admin_id(),
        "-t",
        "-1",
    ])
    .failure()
    .stderr(contains("No permission to revoke"));

    let permissions = run_json(&["get", "resource-permissions", "--id", &resource.id]);
    assert!(permissions
        .as_array()
        .unwrap()
        .iter()
        .any(|permission| permission["aro_foreign_key"] == recipient.as_str()));
}

#[test]
fn adding_a_manager_as_member_keeps_them_manager() {
    let admin = admin_id();
    let user_id = current_user_id(Account::User);
    let group = create_group(&unique_name("managers"), &admin, &[&user_id]);

    passbolt_as(ADMIN)
        .args(["update", "group", "--id", &group.id, "-u", &admin])
        .assert()
        .success();

    let fetched = run_json_as(ADMIN, &["get", "group", "--id", &group.id]);
    let admin_membership = fetched["groups_users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|membership| membership["user_id"] == admin.as_str())
        .cloned()
        .unwrap_or(Value::Null);
    assert_eq!(admin_membership["is_admin"], true, "{fetched}");
}

#[test]
fn deleting_a_folder_moves_its_content_to_the_root() {
    let folder = create_folder(&unique_name("deleted"), &[]);
    let resource = create_resource(
        &unique_name("kept"),
        "p",
        &["--type", "v5-default", "--folder-parent-id", &folder.id],
    );

    run(&["delete", "folder", "--id", &folder.id]);

    let fetched = run_json(&["get", "resource", "--id", &resource.id]);
    assert_eq!(fetched["folder_parent_id"], Value::Null);
}

#[test]
fn deleting_a_folder_with_cascade_deletes_its_content() {
    let folder = create_folder(&unique_name("cascade"), &[]);
    let sub_folder = create_folder(&unique_name("sub"), &["--folder-parent-id", &folder.id]);
    let resource = create_resource(
        &unique_name("gone"),
        "p",
        &["--type", "v5-default", "--folder-parent-id", &sub_folder.id],
    );

    run(&["delete", "folder", "--id", &folder.id, "--cascade"]);

    assert_not_found(Account::User, &["get", "folder", "--id", &sub_folder.id]);
    assert_not_found(Account::User, &["get", "resource", "--id", &resource.id]);
}
