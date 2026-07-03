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

//! End-to-end tests of `migrate-metadata` against a real Passbolt server. The command upgrades
//! every v4 resource of the server: `scripts/e2e.sh` runs them alone, after the other tests.

// Shared with the main suite, which uses more of it.
#[allow(dead_code)]
#[path = "../e2e/common.rs"]
mod common;

use serde_json::Value;

use common::{
    admin_id, assert_signed_by, block_on, create_group, current_user_id, metadata_key_type,
    openpgp_js, private_key, resource_column, run, run_json, run_json_as, sdk_login, unique_name,
    Account, Cleanup, ADMIN,
};

const TOTP_KEY: &str = "JBSWY3DPEHPK3PXP";

const USER_AND_URI: [&str; 4] = ["--username", "e2e", "--uri", "https://e2e.test"];

/// v4 resource of type `slug` created by `account`.
fn create_v4(account: Account, slug: &str, args: &[&str]) -> (Cleanup, String) {
    let name = unique_name(slug);
    let mut create_args = vec!["create", "resource", "--type", slug, "--name", &name];
    create_args.extend_from_slice(args);
    let created = run_json_as(account, &create_args);
    assert_eq!(
        key_type(account, created["id"].as_str().unwrap()),
        Value::Null,
        "{slug} is not created as v4"
    );
    (Cleanup::by(account, "resource", &created), name)
}

fn migrate(args: &[&str]) -> u64 {
    let mut migrate_args = vec!["migrate-metadata"];
    migrate_args.extend_from_slice(args);
    run_json_as(ADMIN, &migrate_args)["upgraded"]
        .as_u64()
        .unwrap()
}

/// The key type of the metadata of resource `id`, `null` for a v4 resource.
fn key_type(account: Account, id: &str) -> Value {
    metadata_key_type(account, id).map_or(Value::Null, Value::from)
}

fn get_as(account: Account, id: &str) -> Value {
    run_json_as(account, &["get", "resource", "--id", id])
}

#[test]
fn every_v4_type_becomes_its_v5_type_its_owner_still_reads() {
    let cases: [(&str, &[&str], &str); 4] = [
        (
            "password-string",
            &["--password", "p1"],
            "v5-password-string",
        ),
        (
            "password-and-description",
            &["--password", "p2", "--description", "d2"],
            "v5-default",
        ),
        (
            "password-description-totp",
            &["--password", "p3", "--totp-key", TOTP_KEY],
            "v5-default-with-totp",
        ),
        // The v4 TOTP type has no username nor URI.
        ("totp", &["--totp-key", TOTP_KEY], "v5-totp-standalone"),
    ];
    let created: Vec<_> = cases
        .iter()
        .map(|(slug, args, _)| {
            let mut args = args.to_vec();
            if *slug != "totp" {
                args.extend(USER_AND_URI);
            }
            create_v4(Account::User, slug, &args)
        })
        .collect();

    migrate(&[]);

    for ((v4_slug, _, v5_slug), (resource, name)) in cases.iter().zip(&created) {
        let fetched = get_as(Account::User, &resource.id);
        assert_eq!(
            resource_column(Account::User, &resource.id, "resource_type"),
            *v5_slug,
            "{v4_slug}: {fetched}"
        );
        assert_eq!(
            key_type(Account::User, &resource.id),
            "user_key",
            "{v4_slug}"
        );
        assert_eq!(fetched["name"], name.as_str(), "{v4_slug}");
        if *v4_slug != "totp" {
            assert_eq!(fetched["username"], "e2e", "{v4_slug}");
            assert_eq!(fetched["uri"], "https://e2e.test", "{v4_slug}");
        }
    }
    let [string, described, with_totp, totp] = [0, 1, 2, 3].map(|index| &created[index].0.id);
    assert_eq!(get_as(Account::User, string)["password"], "p1");
    assert_eq!(get_as(Account::User, described)["password"], "p2");
    // The v4 description, in the secret, is the v5 secret note.
    assert_eq!(
        get_as(Account::User, described)["secret"]["description"],
        "d2"
    );
    assert_eq!(get_as(Account::User, with_totp)["password"], "p3");
    for id in [with_totp, totp] {
        let code = run_json(&["get", "totp", "--id", id]);
        assert_eq!(code["code"].as_str().unwrap().len(), 6, "{code}");
    }
}

#[test]
fn the_administrators_own_personal_resources_stay_readable() {
    let (resource, name) = create_v4(ADMIN, "password-and-description", &["--password", "p"]);

    migrate(&[]);

    let fetched = get_as(ADMIN, &resource.id);
    assert_eq!(key_type(ADMIN, &resource.id), "user_key");
    assert_eq!(fetched["name"], name.as_str());
    assert_eq!(fetched["password"], "p");
}

#[test]
fn a_resource_shared_with_another_user_gets_the_shared_key_both_read() {
    let (resource, name) = create_v4(
        Account::User,
        "password-and-description",
        &["--password", "p"],
    );
    run(&[
        "share",
        "resource",
        "--id",
        &resource.id,
        "-u",
        &admin_id(),
        "-t",
        "1",
    ]);

    migrate(&[]);

    for account in [Account::User, ADMIN] {
        let fetched = get_as(account, &resource.id);
        assert_eq!(key_type(account, &resource.id), "shared_key");
        assert_eq!(fetched["name"], name.as_str());
        assert_eq!(fetched["password"], "p");
    }
}

#[test]
fn a_resource_only_a_group_reads_gets_the_shared_key() {
    let user_id = current_user_id(Account::User);
    let group = create_group(&unique_name("group"), &admin_id(), &[&user_id]);
    let (resource, name) = create_v4(
        Account::User,
        "password-and-description",
        &["--password", "p"],
    );
    run(&[
        "share",
        "resource",
        "--id",
        &resource.id,
        "-g",
        &group.id,
        "-t",
        "15",
    ]);
    run(&[
        "share",
        "resource",
        "--id",
        &resource.id,
        "-u",
        &user_id,
        "-t",
        "-1",
    ]);

    migrate(&[]);

    let fetched = get_as(Account::User, &resource.id);
    assert_eq!(key_type(Account::User, &resource.id), "shared_key");
    assert_eq!(fetched["name"], name.as_str());
    assert_eq!(fetched["password"], "p");
}

#[test]
fn shared_only_leaves_the_personal_resources_in_v4() {
    let (personal, _) = create_v4(
        Account::User,
        "password-and-description",
        &["--password", "p"],
    );
    let (shared, _) = create_v4(
        Account::User,
        "password-and-description",
        &["--password", "p"],
    );
    run(&[
        "share",
        "resource",
        "--id",
        &shared.id,
        "-u",
        &admin_id(),
        "-t",
        "1",
    ]);

    migrate(&["--shared-only"]);

    assert_eq!(key_type(Account::User, &personal.id), Value::Null);
    assert_eq!(key_type(Account::User, &shared.id), "shared_key");
}

#[test]
fn a_second_run_has_nothing_left_to_upgrade() {
    let (_resource, _) = create_v4(Account::User, "password-string", &["--password", "p"]);
    assert!(migrate(&[]) >= 1);

    assert_eq!(migrate(&[]), 0);
}

#[test]
fn only_administrators_can_migrate() {
    common::passbolt()
        .args(["migrate-metadata"])
        .assert()
        .failure();
}

#[test]
fn migrated_metadata_reads_in_openpgp_js_with_the_expected_signatures() {
    let (personal, personal_name) = create_v4(
        Account::User,
        "password-and-description",
        &["--password", "p"],
    );
    let (shared, shared_name) = create_v4(
        Account::User,
        "password-and-description",
        &["--password", "p"],
    );
    run(&[
        "share",
        "resource",
        "--id",
        &shared.id,
        "-u",
        &admin_id(),
        "-t",
        "1",
    ]);

    migrate(&[]);

    let admin = sdk_login(ADMIN);
    let admin_key = block_on(admin.get_me())
        .unwrap()
        .gpg_key
        .unwrap()
        .armored_key
        .unwrap();
    let metadata_keys = block_on(admin.metadata_keys()).unwrap();
    let metadata_key = metadata_keys
        .active_public_key()
        .unwrap()
        .armored()
        .to_owned();
    let user = sdk_login(Account::User);
    let (user_private_key, passphrase) = private_key(Account::User);
    let personal_metadata = block_on(user.get_resource(&personal.id)).unwrap();
    let read = openpgp_js(&serde_json::json!({
        "message": personal_metadata.armored_metadata().unwrap(),
        "decryption_key": user_private_key,
        "passphrase": passphrase,
        "verification_keys": [admin_key],
    }));
    // The administrator signs the metadata they encrypt for the owner.
    assert!(assert_signed_by(&read, 1).contains(&personal_name));
    run(&["list", "resource"]);
    let session_keys = block_on(sdk_login(Account::User).session_keys());
    let shared_metadata = block_on(user.get_resource(&shared.id)).unwrap();
    let read = openpgp_js(&serde_json::json!({
        "message": shared_metadata.armored_metadata().unwrap(),
        "session_key": session_keys.get(&shared.id).unwrap().to_passbolt_string(),
        "verification_keys": [admin_key, metadata_key],
    }));
    assert!(assert_signed_by(&read, 2).contains(&shared_name));
    block_on(user.logout());
    block_on(admin.logout());
}
