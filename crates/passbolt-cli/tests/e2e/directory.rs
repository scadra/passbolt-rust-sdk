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

//! Users and groups, managed by the admin account.

use serde_json::Value;

use crate::common::{
    admin_id, assert_not_found, create_group, create_resource, ids, run, run_as, run_json,
    run_json_as, run_text_as, share_with_user_id, unique_name, Cleanup, ADMIN,
};

fn create_user(first_name: &str) -> (String, Cleanup) {
    let username = format!("{}@passbolt.com", unique_name("user"));
    let created = run_json_as(
        ADMIN,
        &[
            "create",
            "user",
            "--username",
            &username,
            "--firstname",
            first_name,
            "--lastname",
            "E2E",
        ],
    );
    (username, Cleanup::by(ADMIN, "user", &created))
}

/// `(user_id, is_admin)` of each member.
fn members(group_id: &str) -> Vec<(String, bool)> {
    let group = run_json_as(ADMIN, &["get", "group", "--id", group_id]);
    group["users"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .map(|membership: &Value| {
            (
                membership["id"].as_str().unwrap().to_string(),
                membership["is_group_manager"] == true,
            )
        })
        .collect()
}

#[test]
fn created_user_reads_back() {
    let (username, user) = create_user("Edith");

    let fetched = run_json_as(ADMIN, &["get", "user", "--id", &user.id]);

    assert_eq!(fetched["username"], username.as_str());
    assert_eq!(fetched["first_name"], "Edith");
}

#[test]
fn created_user_is_found_by_search() {
    let (username, user) = create_user("Edith");

    assert_eq!(
        ids(&run_json_as(
            ADMIN,
            &["list", "user", "--search", &username]
        )),
        [user.id.as_str()]
    );
}

#[test]
fn renamed_user_reads_back() {
    let (_, user) = create_user("Edith");

    run_as(
        ADMIN,
        &["update", "user", "--id", &user.id, "--firstname", "Frances"],
    );

    assert_eq!(
        run_json_as(ADMIN, &["get", "user", "--id", &user.id])["first_name"],
        "Frances"
    );
}

#[test]
fn promoted_user_becomes_admin() {
    let (_, user) = create_user("Edith");

    run_as(
        ADMIN,
        &["update", "user", "--id", &user.id, "--role", "admin"],
    );

    assert_eq!(
        run_json_as(ADMIN, &["get", "user", "--id", &user.id])["role"],
        "admin"
    );
}

#[test]
fn deleted_user_is_gone() {
    let (_, user) = create_user("Edith");

    run_as(ADMIN, &["delete", "user", "--id", &user.id]);

    assert_not_found(ADMIN, &["get", "user", "--id", &user.id]);
}

#[test]
fn created_group_has_its_manager() {
    let manager = admin_id();
    let group = create_group(&unique_name("group"), &manager, &[]);

    assert_eq!(members(&group.id), [(manager, true)]);
}

#[test]
fn added_member_is_in_the_group() {
    let manager = admin_id();
    let member = share_with_user_id();
    let group = create_group(&unique_name("group"), &manager, &[]);

    run_as(
        ADMIN,
        &["update", "group", "--id", &group.id, "--user", &member],
    );

    assert!(members(&group.id).contains(&(member, false)));
}

#[test]
fn removed_member_leaves_the_group() {
    let manager = admin_id();
    let member = share_with_user_id();
    let group = create_group(&unique_name("group"), &manager, &[]);
    run_as(
        ADMIN,
        &["update", "group", "--id", &group.id, "--user", &member],
    );

    run_as(
        ADMIN,
        &[
            "update", "group", "--id", &group.id, "--delete", "--user", &member,
        ],
    );

    assert_eq!(members(&group.id), [(manager, true)]);
}

#[test]
fn renamed_group_reads_back() {
    let group = create_group(&unique_name("group"), &admin_id(), &[]);
    let new_name = unique_name("renamed");

    run_as(
        ADMIN,
        &["update", "group", "--id", &group.id, "--name", &new_name],
    );

    assert_eq!(
        run_json_as(ADMIN, &["get", "group", "--id", &group.id])["name"],
        new_name.as_str()
    );
}

#[test]
fn created_group_is_listed() {
    let name = unique_name("group");
    let group = create_group(&name, &admin_id(), &[]);

    assert_eq!(
        ids(&run_json(&[
            "list",
            "group",
            "--filter",
            &format!("name={name}")
        ])),
        [group.id.as_str()]
    );
}

#[test]
fn deleted_group_is_gone() {
    let group = create_group(&unique_name("group"), &admin_id(), &[]);

    run_as(ADMIN, &["delete", "group", "--id", &group.id]);

    assert_not_found(ADMIN, &["get", "group", "--id", &group.id]);
}

#[test]
fn users_with_access_to_a_resource_are_listed() {
    let recipient = share_with_user_id();
    let resource = create_resource(&unique_name("resource"), "p", &[]);
    run(&[
        "share",
        "resource",
        "--id",
        &resource.id,
        "--type",
        "1",
        "--user",
        &recipient,
    ]);

    let users = run_json(&["list", "user", "--resource", &resource.id]);

    assert!(ids(&users).contains(&recipient.as_str()), "{users}");
}

#[test]
fn admins_are_listed_without_regular_users() {
    let admins = run_json(&["list", "user", "--admin"]);

    let admin_ids = ids(&admins);
    assert!(admin_ids.contains(&admin_id().as_str()));
    assert!(!admin_ids.contains(&share_with_user_id().as_str()));
}

#[test]
fn group_members_are_listed() {
    let member = share_with_user_id();
    let group = create_group(&unique_name("group"), &admin_id(), &[&member]);

    let users = run_json(&["list", "user", "--group", &group.id]);

    assert!(ids(&users).contains(&member.as_str()), "{users}");
}

#[test]
fn groups_are_listed_by_member_and_by_manager() {
    let manager = admin_id();
    let member = share_with_user_id();
    let group = create_group(&unique_name("group"), &manager, &[&member]);

    for (flag, user) in [("--user", &member), ("--manager", &manager)] {
        let groups = run_json(&["list", "group", flag, user]);
        assert!(
            ids(&groups).contains(&group.id.as_str()),
            "{flag}: {groups}"
        );
    }
}

#[test]
fn user_table_shows_the_profile() {
    let (username, user) = create_user("Edith");

    let shown = run_text_as(ADMIN, &["get", "user", "--id", &user.id]);

    assert!(
        shown.contains(&username) && shown.contains("Edith"),
        "{shown}"
    );
}

#[test]
fn group_table_shows_the_manager() {
    let group = create_group(&unique_name("group"), &admin_id(), &[]);

    let shown = run_text_as(ADMIN, &["get", "group", "--id", &group.id]);

    let manager_row = shown
        .lines()
        .find(|line| line.starts_with(&admin_id()))
        .unwrap_or_else(|| panic!("no manager row: {shown}"));
    assert!(shown.contains("IsGroupManager"), "{shown}");
    assert!(manager_row.trim_end().ends_with("true"), "{shown}");
}

#[test]
fn group_table_shows_the_requested_columns() {
    let member = share_with_user_id();
    let group = create_group(&unique_name("group"), &admin_id(), &[&member]);

    let shown = run_text_as(
        ADMIN,
        &["get", "group", "--id", &group.id, "-c", "Username"],
    );

    assert!(
        shown.contains(&std::env::var("PASSBOLT_E2E_SHARE_WITH").unwrap()),
        "{shown}"
    );
}
