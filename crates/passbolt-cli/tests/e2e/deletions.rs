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

//! Deleting a user or a group that alone owns shared content: the dry-run lists it, the
//! deletion waits for a new owner given with --transfer-to.
//!
//! The e2e user is never actually deleted: every user scenario keeps a blocker in place.

use predicates::str::contains;
use serde_json::Value;

use crate::common::{
    admin_id, create_group, create_resource, current_user_id, passbolt_as, run, run_json,
    run_json_as, share_with_user_id, unique_name, Account, Cleanup, ADMIN, UNKNOWN_ID,
};

const OWNER: i64 = 15;

fn blocked_resource_ids(blockers: &Value) -> Vec<&str> {
    blockers["resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["id"].as_str().unwrap())
        .collect()
}

/// A resource of the e2e user shared with the recipient: only the e2e user owns it.
fn shared_resource_only_the_user_owns() -> Cleanup {
    let resource = create_resource(&unique_name("sole-owner"), "p", &["--type", "v5-default"]);
    run(&[
        "share",
        "resource",
        "--id",
        &resource.id,
        "-u",
        &share_with_user_id(),
        "-t",
        "1",
    ]);
    resource
}

/// A group of the admin (manager) and the e2e user, alone owning a resource the admin reads.
fn group_alone_owning_a_resource() -> (Cleanup, Cleanup) {
    let user_id = current_user_id(Account::User);
    let group = create_group(&unique_name("owner-group"), &admin_id(), &[&user_id]);
    let created = run_json(&[
        "create",
        "resource",
        "--type",
        "v5-default",
        "--name",
        &unique_name("group-owned"),
        "--password",
        "p",
    ]);
    // The admin ends up owning it: clean up as the admin.
    let resource = Cleanup::by(ADMIN, "resource", &created);
    for (aro_flag, aro_id, permission_type) in [
        ("-g", group.id.as_str(), "15"),
        ("-u", admin_id().as_str(), "1"),
        ("-u", user_id.as_str(), "-1"),
    ] {
        run(&[
            "share",
            "resource",
            "--id",
            &resource.id,
            aro_flag,
            aro_id,
            "-t",
            permission_type,
        ]);
    }
    (group, resource)
}

fn group_exists(group: &Cleanup) -> bool {
    passbolt_as(ADMIN)
        .args(["get", "group", "--id", &group.id])
        .output()
        .unwrap()
        .status
        .success()
}

fn delete_group(group: &Cleanup, args: &[&str]) -> assert_cmd::assert::Assert {
    passbolt_as(ADMIN)
        .args(["delete", "group", "--id", &group.id])
        .args(args)
        .assert()
}

#[test]
fn the_group_dry_run_lists_what_only_the_group_owns() {
    let (group, resource) = group_alone_owning_a_resource();

    let blockers = run_json_as(ADMIN, &["delete", "group", "--id", &group.id, "--dry-run"]);

    assert_eq!(blocked_resource_ids(&blockers), [resource.id.as_str()]);
    assert!(group_exists(&group));
}

#[test]
fn a_group_owning_content_alone_is_kept_without_a_transfer() {
    let (group, _resource) = group_alone_owning_a_resource();

    delete_group(&group, &[])
        .failure()
        .stderr(contains("--transfer-to"));

    assert!(group_exists(&group));
}

#[test]
fn a_transfer_to_someone_without_access_is_refused_before_deleting() {
    let (group, _resource) = group_alone_owning_a_resource();

    delete_group(&group, &["--transfer-to", &share_with_user_id()])
        .failure()
        .stderr(contains("has no access"));

    assert!(group_exists(&group));
}

#[test]
fn a_transfer_gives_the_content_and_deletes_the_group() {
    let admin = admin_id();
    let (group, resource) = group_alone_owning_a_resource();

    delete_group(&group, &["--transfer-to", &admin]).success();

    assert!(!group_exists(&group));
    let permissions = run_json_as(
        ADMIN,
        &["get", "resource-permissions", "--id", &resource.id],
    );
    let admin_permission = permissions
        .as_array()
        .unwrap()
        .iter()
        .find(|permission| permission["aro_foreign_key"] == admin.as_str())
        .unwrap();
    assert_eq!(admin_permission["type"], OWNER);
}

#[test]
fn the_user_dry_run_lists_what_only_the_user_owns() {
    let resource = shared_resource_only_the_user_owns();
    let user_id = current_user_id(Account::User);

    let blockers = run_json_as(ADMIN, &["delete", "user", "--id", &user_id, "--dry-run"]);

    assert!(blocked_resource_ids(&blockers).contains(&resource.id.as_str()));
}

#[test]
fn a_user_owning_content_alone_is_kept_without_a_transfer() {
    let _resource = shared_resource_only_the_user_owns();
    let user_id = current_user_id(Account::User);

    passbolt_as(ADMIN)
        .args(["delete", "user", "--id", &user_id])
        .assert()
        .failure()
        .stderr(contains("--transfer-to"));
    passbolt_as(ADMIN)
        .args([
            "delete",
            "user",
            "--id",
            &user_id,
            "--transfer-to",
            UNKNOWN_ID,
        ])
        .assert()
        .failure()
        .stderr(contains("has no access"));

    assert_eq!(current_user_id(Account::User), user_id);
}
