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
fn sharing_with_nobody_changes_nothing() {
    let resource = create_resource(&unique_name("nobody"), "p", &[]);

    share(&["resource", "--id", &resource.id, "-t", "7"]).success();

    let permissions = run_json(&["get", "resource", "permission", "--id", &resource.id]);
    assert_eq!(permissions.as_array().unwrap().len(), 1, "{permissions}");
}

#[test]
fn sharing_again_with_the_same_permission_is_refused() {
    let recipient = share_with_user_id();
    let resource = create_resource(&unique_name("again"), "p", &[]);
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
        "-t",
        "1",
    ])
    .failure()
    .stderr(contains(format!(
        "sharing Resource: Invalid argument: permission for User {recipient} is already Type 1"
    )));
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
    .stderr(contains(
        "Cannot be Deleted as No Matching Permission Exists",
    ));

    let permissions = run_json(&["get", "resource-permissions", "--id", &resource.id]);
    assert!(permissions
        .as_array()
        .unwrap()
        .iter()
        .any(|permission| permission["aro_foreign_key"] == recipient.as_str()));
}

/// `(user_id, is_group_manager)` of each member, as the admin reads the group.
fn members(group_id: &str) -> Vec<(String, bool)> {
    let group = run_json_as(ADMIN, &["get", "group", "--id", group_id]);
    group["users"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .map(|member| {
            (
                member["id"].as_str().unwrap().to_string(),
                member["is_group_manager"] == true,
            )
        })
        .collect()
}

fn update_group(arguments: &[&str]) -> assert_cmd::assert::Assert {
    passbolt_as(ADMIN)
        .args(["update", "group"])
        .args(arguments)
        .assert()
}

#[test]
fn a_member_is_promoted_then_demoted() {
    let user_id = current_user_id(Account::User);
    let group = create_group(&unique_name("roles"), &admin_id(), &[&user_id]);

    update_group(&["--id", &group.id, "-m", &user_id]).success();
    assert!(members(&group.id).contains(&(user_id.clone(), true)));

    update_group(&["--id", &group.id, "-u", &user_id]).success();
    assert!(members(&group.id).contains(&(user_id, false)));
}

#[test]
fn giving_a_member_the_role_they_have_is_refused() {
    let user_id = current_user_id(Account::User);
    let group = create_group(&unique_name("same-role"), &admin_id(), &[&user_id]);

    update_group(&["--id", &group.id, "-u", &user_id])
        .failure()
        .stderr(contains(format!(
            "membership for User {user_id} already Exists with Same Role"
        )));
}

#[test]
fn delete_removes_the_given_managers_and_members() {
    let admin = admin_id();
    let user_id = current_user_id(Account::User);
    let group = create_group(&unique_name("removal"), &admin, &[&user_id]);
    update_group(&["--id", &group.id, "-m", &user_id]).success();

    update_group(&["--id", &group.id, "-d", "-m", &user_id]).success();

    assert_eq!(members(&group.id), [(admin, true)]);
}

#[test]
fn removing_a_non_member_is_refused() {
    let group = create_group(&unique_name("non-member"), &admin_id(), &[]);
    let user_id = current_user_id(Account::User);

    update_group(&["--id", &group.id, "-d", "-u", &user_id])
        .failure()
        .stderr(contains(format!(
            "cannot Delete User {user_id} as it has no membership"
        )));
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
    assert_eq!(fetched["folder_parent_id"], "");
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
