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

//! The CLI options doing what their help says.

use serde_json::Value;

use crate::common::{
    admin_id, create_folder, create_group, create_resource, current_user_id, ids, run, run_json,
    run_text, unique_name, Account,
};

#[test]
fn permission_columns_can_be_chosen() {
    let resource = create_resource(&unique_name("columns"), "p", &[]);

    let table = run_text(&[
        "get",
        "resource-permissions",
        "--id",
        &resource.id,
        "-c",
        "Permission Type",
        "-c",
        "aro_id",
    ]);
    let json = run_json(&[
        "get",
        "resource-permissions",
        "--id",
        &resource.id,
        "-c",
        "type",
    ]);

    let header = table
        .lines()
        .find(|line| line.contains("Type"))
        .unwrap_or_default();
    let header_cells: Vec<&str> = header
        .split('|')
        .map(str::trim)
        .filter(|cell| !cell.is_empty())
        .collect();
    assert_eq!(header_cells, ["Type", "ARO ID"], "{table}");
    assert_eq!(json[0], serde_json::json!({ "type": "Owner" }));
}

#[test]
fn folders_shared_with_any_of_the_groups_are_listed() {
    let user_id = current_user_id(Account::User);
    let admin = admin_id();
    let first_group = create_group(&unique_name("first"), &admin, &[&user_id]);
    let second_group = create_group(&unique_name("second"), &admin, &[&user_id]);
    let first = create_folder(&unique_name("first"), &[]);
    let second = create_folder(&unique_name("second"), &[]);
    let alone = create_folder(&unique_name("alone"), &[]);
    for (folder, group) in [(&first, &first_group), (&second, &second_group)] {
        run(&[
            "share", "folder", "--id", &folder.id, "-g", &group.id, "-t", "1",
        ]);
    }

    let listed = run_json(&[
        "list",
        "folder",
        "-g",
        &first_group.id,
        "-g",
        &second_group.id,
    ]);

    let listed_ids = ids(&listed);
    assert!(listed_ids.contains(&first.id.as_str()), "{listed}");
    assert!(listed_ids.contains(&second.id.as_str()), "{listed}");
    assert!(!listed_ids.contains(&alone.id.as_str()), "{listed}");
}

#[test]
fn a_filter_value_may_hold_an_operator() {
    let uri = format!("https://e2e.test/?{}!=x", unique_name("query"));
    let resource = create_resource(
        &unique_name("operator"),
        "p",
        &["--type", "v5-default", "--uri", &uri],
    );

    let listed = run_json(&["list", "resource", "--filter", &format!("uri={uri}")]);

    let listed: &Vec<Value> = listed.as_array().unwrap();
    assert_eq!(listed.len(), 1, "{listed:?}");
    assert_eq!(listed[0]["id"], resource.id.as_str());
}
