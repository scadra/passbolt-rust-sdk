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
    create_folder, create_resource, run, run_json, share_with_user_id, unique_name, Cleanup,
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
