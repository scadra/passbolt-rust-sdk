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

use passbolt_sdk::resource::upgrade;
use passbolt_sdk::PassboltError;
use rstest::rstest;
use serde_json::{json, Value};

use crate::common::*;

const UPGRADE_PATH: &str = "/metadata/upgrade/resources.json";

/// v4 resource of type `slug`, as the upgrade list returns it with its permissions.
fn v4_resource(slug: &str, permissions: Value) -> Value {
    let mut resource = data::resource_v4(slug, "s3cr3t");
    resource["permissions"] = permissions;
    resource
}

fn shared_permissions() -> Value {
    json!([
        data::permission("p-ada", "User", ADA_ID, 15),
        data::permission("p-betty", "User", BETTY_ID, 1),
    ])
}

/// Server with mk1 listing `resources` to upgrade, then nothing left.
fn server_upgrading(resources: Value) -> FakePassbolt {
    let fake = FakePassbolt::new();
    fake.with_directory();
    fake.with_metadata_settings(
        data::metadata_types_settings(),
        data::metadata_keys_settings(),
    );
    fake.on(
        "GET",
        "/metadata/keys.json",
        data::metadata_keys(&[("mk1", &METADATA)]),
    );
    fake.on("GET", UPGRADE_PATH, resources);
    fake.on("POST", UPGRADE_PATH, json!([]));
    fake
}

async fn upgrade_all(fake: &FakePassbolt) -> Result<usize, PassboltError> {
    let client = login_ada(fake).await;
    upgrade::upgrade_resources(&client, false).await
}

fn sent_resource(fake: &FakePassbolt) -> Value {
    fake.body_of("POST", UPGRADE_PATH)[0].clone()
}

#[rstest]
#[case("password-string", "v5-password-string")]
#[case("password-and-description", "v5-default")]
#[case("password-description-totp", "v5-default-with-totp")]
#[case("totp", "v5-totp-standalone")]
#[tokio::test]
async fn upgrades_each_v4_type_to_its_v5_type(#[case] v4_slug: &str, #[case] v5_slug: &str) {
    let fake = server_upgrading(json!([v4_resource(v4_slug, shared_permissions())]));

    upgrade_all(&fake).await.unwrap();

    let metadata = METADATA.decrypt_json(sent_resource(&fake)["metadata"].as_str().unwrap());
    assert_eq!(
        metadata["resource_type_id"],
        data::resource_type_id(v5_slug)
    );
}

#[tokio::test]
async fn moves_the_cleartext_fields_into_the_metadata() {
    let fake = server_upgrading(json!([v4_resource(
        "password-string",
        shared_permissions()
    )]));

    upgrade_all(&fake).await.unwrap();

    let metadata = METADATA.decrypt_json(sent_resource(&fake)["metadata"].as_str().unwrap());
    assert_eq!(metadata["name"], "GitHub");
    assert_eq!(metadata["username"], "ada");
    assert_eq!(metadata["uris"], json!(["https://github.com"]));
}

#[tokio::test]
async fn shared_resources_use_the_shared_metadata_key() {
    let fake = server_upgrading(json!([v4_resource(
        "password-string",
        shared_permissions()
    )]));

    upgrade_all(&fake).await.unwrap();

    let sent = sent_resource(&fake);
    assert_eq!(sent["metadata_key_type"], "shared_key");
    assert_eq!(sent["id"], RESOURCE_ID);
    assert_eq!(sent["modified_by"], ADA_ID);
    assert!(sent["modified"].is_string());
}

#[tokio::test]
async fn resources_only_one_user_can_read_are_encrypted_for_that_user() {
    let fake = server_upgrading(json!([v4_resource(
        "password-string",
        json!([data::permission("p-betty", "User", BETTY_ID, 15)])
    )]));

    upgrade_all(&fake).await.unwrap();

    let sent = sent_resource(&fake);
    let betty = data::user("betty");
    assert_eq!(sent["metadata_key_type"], "user_key");
    assert_eq!(sent["metadata_key_id"], betty["gpgkey"]["id"]);
    let metadata = sent["metadata"].as_str().unwrap();
    assert_eq!(BETTY.decrypt_json(metadata)["name"], "GitHub");
    assert!(ADA.try_decrypt(metadata).is_none());
}

#[tokio::test]
async fn resources_of_a_single_group_use_the_shared_key() {
    let fake = server_upgrading(json!([v4_resource(
        "password-string",
        json!([data::permission("p-group", "Group", GROUP_ID, 15)])
    )]));

    upgrade_all(&fake).await.unwrap();

    assert_eq!(sent_resource(&fake)["metadata_key_type"], "shared_key");
}

#[tokio::test]
async fn personal_resources_use_the_shared_key_when_personal_keys_are_disallowed() {
    let fake = server_upgrading(json!([v4_resource(
        "password-string",
        ada_owner_permissions()
    )]));
    fake.with_metadata_settings(
        data::metadata_types_settings(),
        json!({ "allow_usage_of_personal_keys": false, "zero_knowledge_key_share": false }),
    );

    upgrade_all(&fake).await.unwrap();

    assert_eq!(sent_resource(&fake)["metadata_key_type"], "shared_key");
}

#[tokio::test]
async fn refuses_when_the_server_does_not_allow_v5_resources() {
    let fake = server_upgrading(json!([v4_resource(
        "password-string",
        shared_permissions()
    )]));
    let mut types = data::metadata_types_settings();
    types["allow_creation_of_v5_resources"] = false.into();
    fake.with_metadata_settings(types, data::metadata_keys_settings());

    let error = upgrade_all(&fake).await.unwrap_err();

    assert!(
        matches!(error, PassboltError::InvalidArgument(_)),
        "{error:?}"
    );
    assert!(fake.requests_to("GET", UPGRADE_PATH).is_empty());
}

#[tokio::test]
async fn upgrades_the_batches_the_server_returns_until_none_is_left() {
    let fake = server_upgrading(json!([v4_resource(
        "password-string",
        shared_permissions()
    )]));
    fake.on_in_turn(
        "POST",
        UPGRADE_PATH,
        vec![(200, json!([v4_resource("totp", shared_permissions())]))],
    );

    let upgraded = upgrade_all(&fake).await;

    assert_eq!(upgraded.unwrap(), 2);
    assert_eq!(fake.requests_to("POST", UPGRADE_PATH).len(), 2);
}

#[tokio::test]
async fn shared_only_asks_the_server_for_shared_resources() {
    let fake = server_upgrading(json!([]));
    let client = login_ada(&fake).await;

    let upgraded = upgrade::upgrade_resources(&client, true).await.unwrap();

    assert_eq!(upgraded, 0);
    let listing = &fake.requests_to("GET", UPGRADE_PATH)[0];
    assert_eq!(
        listing.query_value("filter[is-shared]").as_deref(),
        Some("1")
    );
    assert!(fake.requests_to("POST", UPGRADE_PATH).is_empty());
}

#[tokio::test]
async fn a_conflict_is_replayed_then_reported() {
    let fake = server_upgrading(json!([v4_resource(
        "password-string",
        shared_permissions()
    )]));
    fake.on_error("POST", UPGRADE_PATH, 409);

    let error = upgrade_all(&fake).await.unwrap_err();

    assert!(matches!(error, PassboltError::Api(_)), "{error:?}");
    assert_eq!(fake.requests_to("POST", UPGRADE_PATH).len(), 4);
}

#[tokio::test]
async fn replays_are_counted_over_the_whole_run() {
    let fake = server_upgrading(json!([v4_resource(
        "password-string",
        shared_permissions()
    )]));
    fake.on_error("POST", UPGRADE_PATH, 409);
    let batch = json!([v4_resource("totp", shared_permissions())]);
    fake.on_in_turn("POST", UPGRADE_PATH, vec![(409, Value::Null), (200, batch)]);

    upgrade_all(&fake).await.unwrap_err();

    // One replay, one batch upgraded, then two replays left before giving up.
    assert_eq!(fake.requests_to("POST", UPGRADE_PATH).len(), 5);
}

#[tokio::test]
async fn stops_when_no_listed_resource_can_be_upgraded() {
    let fake = server_upgrading(json!([v4_resource("v5-default", shared_permissions())]));

    let error = upgrade_all(&fake).await.unwrap_err();

    assert!(error.to_string().contains("cannot be upgraded"), "{error}");
    assert!(fake.requests_to("POST", UPGRADE_PATH).is_empty());
}
