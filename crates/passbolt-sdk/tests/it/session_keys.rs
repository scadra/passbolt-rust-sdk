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

use passbolt_sdk::crypto;
use passbolt_sdk::resource::list::list_resources;
use passbolt_sdk::types::Resource;
use passbolt_sdk::ResourceQuery;
use serde_json::{json, Value};

use crate::common::*;

const SESSION_KEYS_PATH: &str = "/metadata/session-keys.json";
const BUNDLE_ID: &str = "4a5b6c7d-0000-4000-8000-0000000005e1";

fn shared_resource() -> Resource {
    data::resource_v5(&data::metadata("GitHub"), &METADATA, "shared_key", "mk1")
}

/// The session key of `resource`'s metadata, as a bundle stores it.
fn session_key_of(resource: &Resource) -> String {
    let metadata_key = crypto::parse_private_key(METADATA.private).unwrap();
    let (_, session_key) = crypto::decrypt_message_keeping_session_key(
        resource.armored_metadata().unwrap(),
        &metadata_key.key,
        METADATA.passphrase,
    )
    .unwrap();
    session_key.to_passbolt_string()
}

/// A bundle of ada with `session_key` for `resource_id`.
fn bundle(resource_id: &str, session_key: &str) -> Value {
    let data = json!({
        "object_type": "PASSBOLT_SESSION_KEYS",
        "session_keys": [{
            "foreign_model": "Resource",
            "foreign_id": resource_id,
            "session_key": session_key,
            "modified": "2025-12-01T10:00:00+00:00"
        }]
    });
    json!([{
        "id": BUNDLE_ID,
        "user_id": ADA_ID,
        "data": ADA.encrypt(&data.to_string()),
        "created": "2025-12-01T10:00:00+00:00",
        "modified": "2025-12-01T10:00:00+00:00"
    }])
}

fn saved_bundle(body: &Value) -> Value {
    ADA.decrypt_json(body["data"].as_str().unwrap())
}

#[tokio::test]
async fn a_known_session_key_decrypts_without_the_metadata_keys() {
    let resource = shared_resource();
    let fake = FakePassbolt::new();
    fake.on(
        "GET",
        SESSION_KEYS_PATH,
        bundle(&resource.id, &session_key_of(&resource)),
    );
    let client = login_ada(&fake).await;

    let metadata = client
        .decrypt_resource_metadata(&resource)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(metadata.name.as_deref(), Some("GitHub"));
    assert!(fake.requests_to("GET", "/metadata/keys.json").is_empty());
}

#[tokio::test]
async fn a_stale_session_key_falls_back_to_the_metadata_key() {
    let resource = shared_resource();
    let fake = FakePassbolt::new();
    fake.on(
        "GET",
        SESSION_KEYS_PATH,
        bundle(&resource.id, &format!("9:{}", "00".repeat(32))),
    );
    fake.on(
        "GET",
        "/metadata/keys.json",
        data::metadata_keys(&[("mk1", &METADATA)]),
    );
    let client = login_ada(&fake).await;

    let metadata = client
        .decrypt_resource_metadata(&resource)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(metadata.name.as_deref(), Some("GitHub"));
}

#[tokio::test]
async fn listing_saves_the_new_session_keys_in_a_new_bundle() {
    let resource = shared_resource();
    let fake = FakePassbolt::new();
    fake.with_directory();
    fake.on(
        "GET",
        "/metadata/keys.json",
        data::metadata_keys(&[("mk1", &METADATA)]),
    );
    fake.on(
        "GET",
        "/resources.json",
        json!([serde_json::to_value(&resource).unwrap()]),
    );
    fake.on("POST", SESSION_KEYS_PATH, Value::Null);
    let client = login_ada(&fake).await;

    list_resources(&client, ResourceQuery::default(), &[], None)
        .await
        .unwrap();

    let saved = saved_bundle(&fake.body_of("POST", SESSION_KEYS_PATH));
    assert_eq!(saved["object_type"], "PASSBOLT_SESSION_KEYS");
    assert_eq!(saved["session_keys"][0]["foreign_id"], resource.id.as_str());
    assert_eq!(
        saved["session_keys"][0]["session_key"],
        session_key_of(&resource).as_str()
    );
}

#[tokio::test]
async fn new_session_keys_update_the_existing_bundle() {
    let known = shared_resource();
    let mut new = shared_resource();
    new.id = "7a5b2c30-0000-4000-8000-0000000000e2".into();
    let fake = FakePassbolt::new();
    fake.with_directory();
    fake.on(
        "GET",
        SESSION_KEYS_PATH,
        bundle(&known.id, &session_key_of(&known)),
    );
    fake.on(
        "GET",
        "/metadata/keys.json",
        data::metadata_keys(&[("mk1", &METADATA)]),
    );
    fake.on(
        "GET",
        "/resources.json",
        json!([
            serde_json::to_value(&known).unwrap(),
            serde_json::to_value(&new).unwrap()
        ]),
    );
    let bundle_path = format!("/metadata/session-keys/{BUNDLE_ID}.json");
    fake.on("PUT", &bundle_path, Value::Null);
    let client = login_ada(&fake).await;

    list_resources(&client, ResourceQuery::default(), &[], None)
        .await
        .unwrap();

    let body = fake.body_of("PUT", &bundle_path);
    assert_eq!(
        body["modified"], "2025-12-01T10:00:00+00:00",
        "the server checks it"
    );
    let saved = saved_bundle(&body);
    let mut ids: Vec<&str> = saved["session_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["foreign_id"].as_str().unwrap())
        .collect();
    ids.sort_unstable();
    assert_eq!(ids, [known.id.as_str(), new.id.as_str()]);
}

#[tokio::test]
async fn nothing_is_saved_when_every_session_key_is_known() {
    let resource = shared_resource();
    let fake = FakePassbolt::new();
    fake.with_directory();
    fake.on(
        "GET",
        SESSION_KEYS_PATH,
        bundle(&resource.id, &session_key_of(&resource)),
    );
    fake.on(
        "GET",
        "/resources.json",
        json!([serde_json::to_value(&resource).unwrap()]),
    );
    let client = login_ada(&fake).await;

    list_resources(&client, ResourceQuery::default(), &[], None)
        .await
        .unwrap();

    assert!(fake.requests_to("POST", SESSION_KEYS_PATH).is_empty());
    assert!(fake
        .requests_to("PUT", &format!("/metadata/session-keys/{BUNDLE_ID}.json"))
        .is_empty());
}
