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

//! What the CLI stores on the server, read by OpenPGP.js as the browser extension does.

use pgp::composed::ArmorOptions;
use serde_json::{json, Value};

use crate::common::{
    assert_signed_by, block_on, create_resource, openpgp_js, private_key, run, sdk_login,
    share_with_user_id, unique_name, Account, Sdk,
};

/// The user's public key and the active metadata public key, armored.
fn public_keys(sdk: &Sdk) -> (String, String) {
    let me = block_on(sdk.get_me()).unwrap();
    let user_key = me.gpg_key.unwrap().armored_key.unwrap();
    let metadata_keys = block_on(sdk.metadata_keys()).unwrap();
    let metadata_key = metadata_keys
        .active_public_key()
        .expect("the server has no active metadata key")
        .to_armored_string(ArmorOptions::default())
        .unwrap();
    (user_key, metadata_key)
}

/// Read `message` with the user's private key in OpenPGP.js.
fn read_as_user(message: &str, verification_keys: &[&str]) -> Value {
    let (key, passphrase) = private_key(Account::User);
    openpgp_js(&json!({
        "message": message,
        "decryption_key": key,
        "passphrase": passphrase,
        "verification_keys": verification_keys,
    }))
}

/// Read the shared metadata of `resource_id` in OpenPGP.js, with its session key saved by the
/// CLI's last listing.
fn read_shared_metadata(sdk: &Sdk, resource_id: &str, verification_keys: &[&str]) -> Value {
    let resource = block_on(sdk.get_resource(resource_id)).unwrap();
    assert_eq!(resource.metadata_key_type.as_deref(), Some("shared_key"));
    let session_keys = block_on(sdk.session_keys());
    let session_key = session_keys
        .get(resource_id)
        .expect("the listing saved no session key for the resource");
    openpgp_js(&json!({
        "message": resource.armored_metadata().unwrap(),
        "session_key": session_key.to_passbolt_string(),
        "verification_keys": verification_keys,
    }))
}

fn shared_resource(name: &str) -> crate::common::Cleanup {
    let resource = create_resource(name, "s3cr3t", &["--type", "v5-default"]);
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
    // The listing saves the session key of the new shared metadata.
    run(&["list", "resource"]);
    resource
}

#[test]
fn personal_metadata_and_secret_are_signed_by_the_user() {
    let name = unique_name("interop");
    let resource = create_resource(&name, "s3cr3t", &["--type", "v5-default"]);
    let sdk = sdk_login(Account::User);
    let (user_key, _) = public_keys(&sdk);

    let stored = block_on(sdk.get_resource(&resource.id)).unwrap();
    let metadata = read_as_user(stored.armored_metadata().unwrap(), &[&user_key]);
    let secret_message = stored.secrets[0].data.as_deref().unwrap();
    let secret = read_as_user(secret_message, &[&user_key]);

    assert!(assert_signed_by(&metadata, 1).contains(&name));
    assert!(assert_signed_by(&secret, 1).contains("s3cr3t"));
    block_on(sdk.logout());
}

#[test]
fn shared_metadata_is_signed_by_the_user_and_the_metadata_key() {
    let name = unique_name("interop");
    let resource = shared_resource(&name);
    let sdk = sdk_login(Account::User);
    let (user_key, metadata_key) = public_keys(&sdk);

    let metadata = read_shared_metadata(&sdk, &resource.id, &[&user_key, &metadata_key]);

    assert!(assert_signed_by(&metadata, 2).contains(&name));
    block_on(sdk.logout());
}

#[test]
fn updated_shared_metadata_is_signed_by_both_keys_again() {
    let resource = shared_resource(&unique_name("interop"));
    let new_name = unique_name("interop-renamed");
    run(&[
        "update",
        "resource",
        "--id",
        &resource.id,
        "--name",
        &new_name,
    ]);
    run(&["list", "resource"]);
    let sdk = sdk_login(Account::User);
    let (user_key, metadata_key) = public_keys(&sdk);

    let metadata = read_shared_metadata(&sdk, &resource.id, &[&user_key, &metadata_key]);

    assert!(assert_signed_by(&metadata, 2).contains(&new_name));
    block_on(sdk.logout());
}

#[test]
fn the_session_keys_bundle_is_signed_by_the_user() {
    shared_resource(&unique_name("interop"));
    let sdk = sdk_login(Account::User);
    let (user_key, _) = public_keys(&sdk);

    let bundles = block_on(sdk.session_keys_bundles()).unwrap();

    assert!(!bundles.is_empty(), "no session keys bundle");
    for bundle in bundles {
        let read = read_as_user(&bundle.data, &[&user_key]);
        assert!(assert_signed_by(&read, 1).contains("PASSBOLT_SESSION_KEYS"));
    }
    block_on(sdk.logout());
}
