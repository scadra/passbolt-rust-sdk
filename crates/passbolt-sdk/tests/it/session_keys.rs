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

use futures_executor::block_on;
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
    let (_, session_key) = block_on(crypto::decrypt_message_keeping_session_key(
        resource.armored_metadata().unwrap(),
        &metadata_key,
        METADATA.passphrase,
    ))
    .unwrap();
    session_key.to_passbolt_string()
}

const BUNDLE_MODIFIED: &str = "2025-12-01T10:00:00+00:00";

fn entry(foreign_model: &str, foreign_id: &str, session_key: &str) -> Value {
    json!({
        "foreign_model": foreign_model,
        "foreign_id": foreign_id,
        "session_key": session_key,
        "modified": "2025-11-01T10:00:00+00:00"
    })
}

/// A bundle of ada holding `entries`.
fn bundle_with(id: &str, modified: &str, entries: &Value) -> Value {
    let data = json!({ "object_type": "PASSBOLT_SESSION_KEYS", "session_keys": entries });
    json!({
        "id": id,
        "user_id": ADA_ID,
        "data": ADA.encrypt(&data.to_string()),
        "created": modified,
        "modified": modified
    })
}

/// Ada's only bundle, with `session_key` for `resource_id`.
fn bundle(resource_id: &str, session_key: &str) -> Value {
    json!([bundle_with(
        BUNDLE_ID,
        BUNDLE_MODIFIED,
        &json!([entry("Resource", resource_id, session_key)])
    )])
}

fn saved_bundle(body: &Value) -> Value {
    ADA.decrypt_json(body["data"].as_str().unwrap())
}

/// The bundles stored on the fake server, decrypted.
fn stored_bundles(fake: &FakePassbolt) -> Vec<Value> {
    fake.stored("GET", SESSION_KEYS_PATH)
        .as_array()
        .unwrap()
        .iter()
        .map(saved_bundle)
        .collect()
}

fn entries_of(bundle: &Value) -> Vec<(String, String)> {
    let mut entries: Vec<(String, String)> = bundle["session_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            (
                entry["foreign_model"].as_str().unwrap().to_string(),
                entry["foreign_id"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    entries.sort();
    entries
}

/// Server with the metadata key, serving `resources`.
fn server_listing(resources: &[&Resource]) -> FakePassbolt {
    let fake = FakePassbolt::new();
    fake.with_directory();
    fake.on(
        "GET",
        "/metadata/keys.json",
        data::metadata_keys(&[("mk1", &METADATA)]),
    );
    serve(&fake, resources);
    fake
}

fn serve(fake: &FakePassbolt, resources: &[&Resource]) {
    fake.on(
        "GET",
        "/resources.json",
        resources
            .iter()
            .map(|resource| serde_json::to_value(resource).unwrap())
            .collect(),
    );
}

fn resource_with_id(id: &str) -> Resource {
    let mut resource = shared_resource();
    resource.id = id.into();
    resource
}

async fn list(client: &Client) {
    list_resources(client, ResourceQuery::default(), &[], None)
        .await
        .unwrap();
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
    let fake = server_listing(&[&resource]);
    let client = login_ada(&fake).await;

    list(&client).await;

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
    let new = resource_with_id("7a5b2c30-0000-4000-8000-0000000000e2");
    let fake = server_listing(&[&known, &new]);
    fake.on(
        "GET",
        SESSION_KEYS_PATH,
        bundle(&known.id, &session_key_of(&known)),
    );
    let client = login_ada(&fake).await;

    list(&client).await;

    let body = fake.body_of("PUT", &format!("/metadata/session-keys/{BUNDLE_ID}.json"));
    assert_eq!(body["modified"], BUNDLE_MODIFIED, "the server checks it");
    assert_eq!(
        entries_of(&saved_bundle(&body)),
        [
            ("Resource".into(), known.id.clone()),
            ("Resource".into(), new.id.clone())
        ]
    );
}

#[tokio::test]
async fn each_entry_keeps_the_modified_of_its_resource() {
    let resource = shared_resource();
    let fake = server_listing(&[&resource]);
    let client = login_ada(&fake).await;

    list(&client).await;

    let saved = saved_bundle(&fake.body_of("POST", SESSION_KEYS_PATH));
    assert_eq!(
        saved["session_keys"][0]["modified"],
        resource.modified.unwrap().to_rfc3339().as_str()
    );
}

#[tokio::test]
async fn a_second_listing_in_the_same_session_saves_on_the_updated_bundle() {
    let first = shared_resource();
    let second = resource_with_id("7a5b2c30-0000-4000-8000-0000000000e2");
    let fake = server_listing(&[&first]);
    let client = login_ada(&fake).await;
    list(&client).await;
    serve(&fake, &[&first, &second]);

    list(&client).await;

    let bundles = stored_bundles(&fake);
    assert_eq!(bundles.len(), 1);
    assert_eq!(
        entries_of(&bundles[0]),
        [
            ("Resource".into(), first.id.clone()),
            ("Resource".into(), second.id.clone())
        ]
    );
}

#[tokio::test]
async fn a_bundle_changed_by_another_client_is_read_again_then_saved() {
    let resource = shared_resource();
    let fake = server_listing(&[&resource]);
    fake.on(
        "GET",
        SESSION_KEYS_PATH,
        json!([bundle_with(BUNDLE_ID, BUNDLE_MODIFIED, &json!([]))]),
    );
    let client = login_ada(&fake).await;
    client.session_keys().await;
    // Another client adds a session key meanwhile.
    fake.on(
        "GET",
        SESSION_KEYS_PATH,
        json!([bundle_with(
            BUNDLE_ID,
            "2025-12-02T10:00:00+00:00",
            &json!([entry(
                "Resource",
                "7a5b2c30-0000-4000-8000-0000000000e9",
                &format!("9:{}", "22".repeat(32))
            )])
        )]),
    );

    list(&client).await;

    assert_eq!(
        fake.requests_to("PUT", &format!("/metadata/session-keys/{BUNDLE_ID}.json"))
            .len(),
        2,
        "the first one conflicts"
    );
    assert_eq!(
        entries_of(&stored_bundles(&fake)[0]),
        [
            ("Resource".into(), resource.id.clone()),
            (
                "Resource".into(),
                "7a5b2c30-0000-4000-8000-0000000000e9".into()
            )
        ]
    );
}

#[tokio::test]
async fn session_keys_of_other_models_are_kept() {
    let resource = shared_resource();
    let fake = server_listing(&[&resource]);
    fake.on(
        "GET",
        SESSION_KEYS_PATH,
        json!([bundle_with(
            BUNDLE_ID,
            BUNDLE_MODIFIED,
            &json!([entry(
                "Folder",
                FOLDER_ID,
                &format!("9:{}", "11".repeat(32))
            )])
        )]),
    );
    let client = login_ada(&fake).await;

    list(&client).await;

    assert_eq!(
        entries_of(&stored_bundles(&fake)[0]),
        [
            ("Folder".into(), FOLDER_ID.into()),
            ("Resource".into(), resource.id.clone())
        ]
    );
}

#[tokio::test]
async fn older_bundles_are_merged_into_the_latest_then_deleted() {
    const OLDER_ID: &str = "4a5b6c7d-0000-4000-8000-0000000005e0";
    let known = shared_resource();
    let new = resource_with_id("7a5b2c30-0000-4000-8000-0000000000e2");
    let fake = server_listing(&[&known, &new]);
    fake.on(
        "GET",
        SESSION_KEYS_PATH,
        json!([
            bundle_with(BUNDLE_ID, BUNDLE_MODIFIED, &json!([])),
            bundle_with(
                OLDER_ID,
                "2025-11-01T10:00:00+00:00",
                &json!([entry("Resource", &known.id, &session_key_of(&known))])
            ),
        ]),
    );
    let client = login_ada(&fake).await;

    list(&client).await;

    assert_eq!(
        fake.requests_to("DELETE", &format!("/metadata/session-keys/{OLDER_ID}.json"))
            .len(),
        1
    );
    let bundles = stored_bundles(&fake);
    assert_eq!(bundles.len(), 1);
    assert_eq!(
        entries_of(&bundles[0]),
        [
            ("Resource".into(), known.id.clone()),
            ("Resource".into(), new.id.clone())
        ]
    );
}

#[tokio::test]
async fn a_failed_save_does_not_fail_the_listing() {
    let resource = shared_resource();
    let fake = server_listing(&[&resource]);
    fake.on_error("POST", SESSION_KEYS_PATH, 500);
    let client = login_ada(&fake).await;

    let views = list_resources(&client, ResourceQuery::default(), &[], None)
        .await
        .unwrap();

    assert_eq!(views[0].name, "GitHub");
}

#[tokio::test]
async fn nothing_is_saved_when_every_session_key_is_known() {
    let resource = shared_resource();
    let fake = server_listing(&[&resource]);
    fake.on(
        "GET",
        SESSION_KEYS_PATH,
        bundle(&resource.id, &session_key_of(&resource)),
    );
    let client = login_ada(&fake).await;

    list(&client).await;

    assert!(fake.requests_to("POST", SESSION_KEYS_PATH).is_empty());
    assert!(fake
        .requests_to("PUT", &format!("/metadata/session-keys/{BUNDLE_ID}.json"))
        .is_empty());
}

#[tokio::test]
async fn a_single_resource_read_keeps_its_session_key_until_saved() {
    let resource = shared_resource();
    let fake = server_listing(&[&resource]);
    let client = login_ada(&fake).await;
    client.decrypt_resource_metadata(&resource).await.unwrap();
    assert!(fake.requests_to("POST", SESSION_KEYS_PATH).is_empty());

    client.save_pending_session_keys().await.unwrap();

    let saved = saved_bundle(&fake.body_of("POST", SESSION_KEYS_PATH));
    assert_eq!(saved["session_keys"][0]["foreign_id"], resource.id.as_str());
    assert_eq!(client.pending_session_keys_count(), 0);
    assert_eq!(client.saved_session_keys_count(), 1);
}

#[tokio::test]
async fn a_resource_read_twice_is_saved_once() {
    let resource = shared_resource();
    let fake = server_listing(&[&resource]);
    let client = login_ada(&fake).await;

    client.decrypt_resource_metadata(&resource).await.unwrap();
    client.decrypt_resource_metadata(&resource).await.unwrap();

    assert_eq!(client.pending_session_keys_count(), 1);
}

#[tokio::test]
async fn the_session_keys_saved_by_a_listing_are_counted() {
    let resource = shared_resource();
    let fake = server_listing(&[&resource]);
    let client = login_ada(&fake).await;

    list(&client).await;

    assert_eq!(client.saved_session_keys_count(), 1);
    assert_eq!(client.pending_session_keys_count(), 0);
}
