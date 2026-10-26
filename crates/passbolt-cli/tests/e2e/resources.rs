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

use chrono::{DateTime, Duration, Utc};
use serde_json::Value;

use crate::common::{
    assert_not_found, create_resource, ids, resource_column, run, run_json, run_text, unique_name,
    Account,
};

fn get(id: &str) -> Value {
    run_json(&["get", "resource", "--id", id])
}

#[test]
fn created_resource_reads_back_decrypted() {
    let name = unique_name("resource");
    let resource = create_resource(
        &name,
        "first-password",
        &["--username", "e2e", "--uri", "https://e2e.test"],
    );

    let fetched = get(&resource.id);

    assert_eq!(fetched["name"], name.as_str());
    assert_eq!(fetched["username"], "e2e");
    assert_eq!(fetched["uri"], "https://e2e.test");
    assert_eq!(fetched["password"], "first-password");
}

#[test]
fn created_description_reads_back() {
    let resource = create_resource(
        &unique_name("resource"),
        "p",
        &["--description", "first description"],
    );

    let shown = run_text(&["get", "resource", "--id", &resource.id]);

    assert!(shown.contains("first description"), "{shown}");
}

#[test]
fn updated_password_reads_back() {
    let resource = create_resource(&unique_name("resource"), "first-password", &[]);

    run(&[
        "update",
        "resource",
        "--id",
        &resource.id,
        "--password",
        "second-password",
    ]);

    assert_eq!(get(&resource.id)["password"], "second-password");
}

#[test]
fn updated_uri_reads_back() {
    let resource = create_resource(
        &unique_name("resource"),
        "p",
        &["--uri", "https://before.test"],
    );

    run(&[
        "update",
        "resource",
        "--id",
        &resource.id,
        "--uri",
        "https://after.test",
    ]);

    assert_eq!(get(&resource.id)["uri"], "https://after.test");
}

#[test]
fn updated_description_reads_back() {
    let resource = create_resource(&unique_name("resource"), "p", &["--description", "before"]);

    run(&[
        "update",
        "resource",
        "--id",
        &resource.id,
        "--description",
        "after",
    ]);

    let shown = run_text(&["get", "resource", "--id", &resource.id]);
    assert!(shown.contains("after"), "{shown}");
}

#[test]
fn expiry_is_set_then_cleared() {
    let resource = create_resource(&unique_name("resource"), "p", &["--expiry", "7d"]);
    let expires_at: DateTime<Utc> = resource_column(Account::User, &resource.id, "expired_at")
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let in_seven_days = Utc::now() + Duration::days(7);
    assert!(
        (expires_at - in_seven_days).num_minutes().abs() < 60,
        "{expires_at}"
    );

    run(&[
        "update",
        "resource",
        "--id",
        &resource.id,
        "--expiry",
        "none",
    ]);

    assert!(
        resource_column(Account::User, &resource.id, "expired_at").is_null(),
        "expiry not cleared"
    );
}

#[test]
fn creator_owns_the_resource() {
    let resource = create_resource(&unique_name("resource"), "p", &[]);

    let permissions = run_json(&["get", "resource-permissions", "--id", &resource.id]);

    assert_eq!(permissions.as_array().unwrap().len(), 1);
    assert_eq!(permissions[0]["type"], 15);
}

#[test]
fn created_resource_is_listed_by_filter_search_and_own() {
    let name = unique_name("resource");
    let resource = create_resource(&name, "p", &[]);
    let by_name = format!("name={name}");

    for args in [
        ["list", "resource", "--filter", by_name.as_str()].as_slice(),
        &["list", "resource", "--search", &name],
        &["list", "resource", "--own", "--search", &name],
    ] {
        assert_eq!(ids(&run_json(args)), [resource.id.as_str()], "{args:?}");
    }
}

#[test]
fn list_shows_the_requested_columns() {
    let name = unique_name("resource");
    let _resource = create_resource(&name, "column-password", &["--username", "column-user"]);

    let table = run_text(&[
        "list", "resource", "--search", &name, "-c", "Name", "-c", "Password",
    ]);

    assert!(
        table.contains(&name) && table.contains("column-password"),
        "{table}"
    );
    assert!(
        !table.contains("column-user"),
        "username column not requested: {table}"
    );
}

#[test]
fn deleted_resource_is_gone() {
    let resource = create_resource(&unique_name("resource"), "p", &[]);

    run(&["delete", "resource", "--id", &resource.id]);

    assert_not_found(Account::User, &["get", "resource", "--id", &resource.id]);
}

#[test]
fn renamed_resource_reads_back() {
    let resource = create_resource(&unique_name("resource"), "p", &[]);
    let new_name = unique_name("renamed");

    run(&[
        "update",
        "resource",
        "--id",
        &resource.id,
        "--name",
        &new_name,
    ]);

    assert_eq!(get(&resource.id)["name"], new_name.as_str());
}

#[test]
fn table_output_shows_the_decrypted_fields() {
    let name = unique_name("resource");
    let resource = create_resource(&name, "table-password", &["--username", "table-user"]);

    let shown = run_text(&["get", "resource", "--id", &resource.id]);

    for expected in [name.as_str(), "table-user", "table-password"] {
        assert!(shown.contains(expected), "{expected} missing: {shown}");
    }
}

#[test]
fn v5_resources_read_back_with_their_decrypted_name() {
    let resources = run_json(&["list", "resource", "-c", "id", "-c", "resource_type"]);
    let v5_ids: Vec<&str> = resources
        .as_array()
        .unwrap()
        .iter()
        .filter(|resource| {
            resource["resource_type"]
                .as_str()
                .is_some_and(|slug| slug.starts_with("v5-"))
        })
        .filter_map(|resource| resource["id"].as_str())
        .take(10)
        .collect();
    assert!(!v5_ids.is_empty(), "the server has no v5 resource for ada");

    for id in v5_ids {
        let name = &get(id)["name"];
        assert!(
            name.as_str().is_some_and(|name| !name.is_empty()),
            "{id}: {name}"
        );
    }
}
