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

//! `generate` and `--generate`, from the password policies of the server.

use crate::common::{run_json, unique_name, Cleanup};

#[test]
fn generate_follows_the_password_policies_of_the_server() {
    let generated = run_json(&["generate"]);

    let secret = generated["secret"].as_str().unwrap();
    assert!(!secret.is_empty());
    assert_ne!(generated["strength"], "not_available");
}

#[test]
fn a_resource_is_created_with_a_generated_password() {
    let resource = Cleanup::new(
        "resource",
        &run_json(&[
            "create",
            "resource",
            "--name",
            &unique_name("generated"),
            "--generate",
        ]),
    );

    let read = run_json(&["get", "resource", "--id", &resource.id]);

    assert!(
        read["password"]
            .as_str()
            .is_some_and(|password| password.len() >= 8),
        "{read}"
    );
}

#[test]
fn update_generate_replaces_the_password() {
    let resource = Cleanup::new(
        "resource",
        &run_json(&[
            "create",
            "resource",
            "--name",
            &unique_name("regenerated"),
            "--password",
            "old-password",
        ]),
    );

    run_json(&["update", "resource", "--id", &resource.id, "--generate"]);

    let read = run_json(&["get", "resource", "--id", &resource.id]);
    assert_ne!(read["password"], "old-password");
}
