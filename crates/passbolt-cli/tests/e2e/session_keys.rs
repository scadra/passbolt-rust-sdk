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

//! The session keys of shared metadata, as the CLI and the SDK save them on the server.

use passbolt_sdk::resource::list::list_resources;
use passbolt_sdk::ResourceQuery;
use serde_json::json;

use crate::common::{
    block_on, create_resource, openpgp_js, private_key, run, sdk_login, share_with_user_id,
    unique_name, Account, Cleanup, Sdk,
};

fn shared_resource() -> Cleanup {
    let resource = create_resource(&unique_name("session-key"), "p", &["--type", "v5-default"]);
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

fn list(sdk: &Sdk) {
    block_on(list_resources(sdk, ResourceQuery::default(), &[], None)).unwrap();
}

/// The user's bundles as stored, decrypted with OpenPGP.js.
fn stored_bundles() -> Vec<serde_json::Value> {
    let sdk = sdk_login(Account::User);
    let (key, passphrase) = private_key(Account::User);
    let bundles = block_on(sdk.session_keys_bundles()).unwrap();
    block_on(sdk.logout());
    bundles
        .iter()
        .map(|bundle| {
            let read = openpgp_js(&json!({
                "message": bundle.data,
                "decryption_key": key,
                "passphrase": passphrase,
                "verification_keys": [],
            }));
            serde_json::from_str(read["text"].as_str().unwrap()).unwrap()
        })
        .collect()
}

fn stored_entry(resource_id: &str) -> Option<serde_json::Value> {
    stored_bundles().into_iter().find_map(|bundle| {
        bundle["session_keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["foreign_id"] == resource_id)
            .cloned()
    })
}

#[test]
fn listing_saves_the_session_key_with_the_resource_modified_date() {
    let resource = shared_resource();

    run(&["list", "resource"]);

    let entry = stored_entry(&resource.id).expect("no session key saved");
    assert_eq!(entry["foreign_model"], "Resource");
    let sdk = sdk_login(Account::User);
    let modified = block_on(sdk.get_resource(&resource.id))
        .unwrap()
        .modified
        .unwrap();
    block_on(sdk.logout());
    let saved_modified =
        chrono::DateTime::parse_from_rfc3339(entry["modified"].as_str().unwrap()).unwrap();
    assert_eq!(saved_modified, modified);
}

#[test]
fn a_long_lived_session_saves_its_new_session_keys_again() {
    let sdk = sdk_login(Account::User);
    let first = shared_resource();
    list(&sdk);
    let second = shared_resource();

    list(&sdk);

    block_on(sdk.logout());
    assert!(stored_entry(&first.id).is_some());
    assert!(
        stored_entry(&second.id).is_some(),
        "the second save was lost"
    );
}

#[test]
fn two_sessions_saving_meanwhile_keep_both_session_keys() {
    let first_session = sdk_login(Account::User);
    let second_session = sdk_login(Account::User);
    block_on(first_session.session_keys());
    block_on(second_session.session_keys());
    let first = shared_resource();
    list(&first_session);
    let second = shared_resource();

    // Its bundle changed since it read it: the server answers 409, it reads it again.
    list(&second_session);

    block_on(first_session.logout());
    block_on(second_session.logout());
    assert!(
        stored_entry(&first.id).is_some(),
        "the other session's key was lost"
    );
    assert!(stored_entry(&second.id).is_some());
}

#[test]
fn the_user_keeps_a_single_bundle() {
    shared_resource();

    run(&["list", "resource"]);

    assert_eq!(stored_bundles().len(), 1);
}
