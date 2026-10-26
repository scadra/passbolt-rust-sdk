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

use crate::common::{
    assert_not_found, create_folder, create_resource, ids, run, run_json, unique_name, Account,
};

#[test]
fn resource_moved_into_a_folder_is_listed_there() {
    let folder = create_folder(&unique_name("folder"), &[]);
    let resource = create_resource(&unique_name("resource"), "p", &[]);

    run(&[
        "move",
        "resource",
        "--id",
        &resource.id,
        "--folder-parent-id",
        &folder.id,
    ]);

    assert_eq!(
        ids(&run_json(&["list", "resource", "--folder", &folder.id])),
        [resource.id.as_str()]
    );
}

#[test]
fn resource_created_in_a_folder_is_listed_there() {
    let folder = create_folder(&unique_name("folder"), &[]);
    let resource = create_resource(
        &unique_name("resource"),
        "p",
        &["--folder-parent-id", &folder.id],
    );

    assert_eq!(
        ids(&run_json(&["list", "resource", "--folder", &folder.id])),
        [resource.id.as_str()]
    );
}

#[test]
fn renamed_folder_reads_back() {
    let folder = create_folder(&unique_name("folder"), &[]);
    let new_name = unique_name("renamed");

    run(&["update", "folder", "--id", &folder.id, "--name", &new_name]);

    assert_eq!(
        run_json(&["get", "folder", "--id", &folder.id])["name"],
        new_name.as_str()
    );
}

#[test]
fn moved_folder_has_its_new_parent() {
    let parent = create_folder(&unique_name("parent"), &[]);
    let child = create_folder(&unique_name("child"), &[]);

    run(&[
        "move",
        "folder",
        "--id",
        &child.id,
        "--folder-parent-id",
        &parent.id,
    ]);

    assert_eq!(
        run_json(&["get", "folder", "--id", &child.id])["folder_parent_id"],
        parent.id.as_str()
    );
    assert_eq!(
        ids(&run_json(&["list", "folder", "--folder", &parent.id])),
        [child.id.as_str()]
    );
}

#[test]
fn created_folder_is_found_by_search() {
    let name = unique_name("folder");
    let folder = create_folder(&name, &[]);

    assert_eq!(
        ids(&run_json(&["list", "folder", "--search", &name])),
        [folder.id.as_str()]
    );
}

#[test]
fn creator_owns_the_folder() {
    let folder = create_folder(&unique_name("folder"), &[]);

    let permissions = run_json(&["get", "folder-permissions", "--id", &folder.id]);

    assert_eq!(permissions.as_array().unwrap().len(), 1);
    assert_eq!(permissions[0]["type"], 15);
}

#[test]
fn deleted_folder_is_gone() {
    let folder = create_folder(&unique_name("folder"), &[]);

    run(&["delete", "folder", "--id", &folder.id]);

    assert_not_found(Account::User, &["get", "folder", "--id", &folder.id]);
}

#[test]
fn resource_moved_back_to_the_root_has_no_parent() {
    let folder = create_folder(&unique_name("folder"), &[]);
    let resource = create_resource(
        &unique_name("resource"),
        "p",
        &["--folder-parent-id", &folder.id],
    );

    run(&["move", "resource", "--id", &resource.id]);

    assert_eq!(
        run_json(&["get", "resource", "--id", &resource.id])["folder_parent_id"],
        ""
    );
}

#[test]
fn every_resource_of_a_large_folder_is_listed() {
    const COUNT: usize = 25;
    let folder = create_folder(&unique_name("large"), &[]);
    let resources: Vec<_> = (0..COUNT)
        .map(|index| {
            create_resource(
                &unique_name(&format!("item{index}")),
                "p",
                &["--folder-parent-id", &folder.id],
            )
        })
        .collect();

    let listed = run_json(&["list", "resource", "--folder", &folder.id]);

    let mut listed_ids = ids(&listed);
    listed_ids.sort_unstable();
    let mut created_ids: Vec<&str> = resources
        .iter()
        .map(|resource| resource.id.as_str())
        .collect();
    created_ids.sort_unstable();
    assert_eq!(listed_ids, created_ids, "missing or duplicated resources");
}
