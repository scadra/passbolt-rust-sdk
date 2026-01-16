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

use passbolt_sdk::resource::create::{self, NewResource};
use passbolt_sdk::types::{CustomField, TotpData};
use passbolt_sdk::PassboltError;
use rstest::rstest;
use serde_json::{json, Value};

use crate::common::*;

const ADA_GPGKEY_ID: &str = "8b6c3a10-0000-4000-8000-000000008888";
const CUSTOM_FIELD_ID: &str = "0f7b6a51-0000-4000-8000-0000000000c1";

/// Server creating v5 resources by default, with `keys` settings and the metadata key mk1.
pub fn v5_server(keys_settings: Value) -> FakePassbolt {
    let fake = FakePassbolt::new();
    fake.with_directory();
    fake.with_metadata_settings(data::metadata_types_settings(), keys_settings);
    fake.on(
        "GET",
        "/metadata/keys.json",
        data::metadata_keys(&[("mk1", &METADATA)]),
    );
    fake.on(
        "POST",
        "/resources.json",
        serde_json::to_value(data::resource_v5(
            &data::metadata("GitHub"),
            &ADA,
            "user_key",
            ADA_GPGKEY_ID,
        ))
        .unwrap(),
    );
    fake
}

pub fn github() -> NewResource {
    NewResource {
        name: "GitHub".into(),
        username: Some("ada".into()),
        uris: vec!["https://github.com".into()],
        description: Some("prod".into()),
        password: Some("s3cr3t".into()),
        ..NewResource::default()
    }
}

fn totp() -> TotpData {
    TotpData {
        secret_key: Some("JBSWY3DPEHPK3PXP".into()),
        algorithm: Some("SHA1".into()),
        digits: Some(6),
        period: Some(30),
        issuer: None,
    }
}

pub async fn create(
    fake: &FakePassbolt,
    new_resource: &NewResource,
) -> Result<Value, PassboltError> {
    let client = login_ada(fake).await;
    create::create_resource(&client, new_resource).await?;
    Ok(fake.body_of("POST", "/resources.json"))
}

async fn refused(fake: &FakePassbolt, new_resource: &NewResource) -> String {
    let error = create(fake, new_resource).await.unwrap_err();
    assert!(
        matches!(error, PassboltError::InvalidArgument(_)),
        "{error:?}"
    );
    assert!(fake.requests_to("POST", "/resources.json").is_empty());
    error.to_string()
}

fn ada_secret(body: &Value) -> Value {
    serde_json::from_str(&ADA.decrypt_signed(secret_of(body, ADA_ID), &[&ADA])).unwrap()
}

#[tokio::test]
async fn creates_personal_v5_metadata_signed_by_the_user() {
    let fake = v5_server(data::metadata_keys_settings());

    let body = create(&fake, &github()).await.unwrap();

    assert_eq!(
        body["resource_type_id"],
        data::resource_type_id("v5-default")
    );
    assert_eq!(body["metadata_key_type"], "user_key");
    assert_eq!(body["metadata_key_id"], ADA_GPGKEY_ID);
    for clear_field in ["name", "username", "uri", "description"] {
        assert!(
            body.get(clear_field).is_none(),
            "{clear_field} sent in clear"
        );
    }
    let metadata: Value =
        serde_json::from_str(&ADA.decrypt_signed(body["metadata"].as_str().unwrap(), &[&ADA]))
            .unwrap();
    assert_eq!(
        metadata,
        json!({
            "object_type": "PASSBOLT_RESOURCE_METADATA",
            "resource_type_id": data::resource_type_id("v5-default"),
            "name": "GitHub",
            "username": "ada",
            "uris": ["https://github.com"],
            "description": "prod"
        })
    );
    assert_eq!(
        ada_secret(&body),
        json!({"object_type": "PASSBOLT_SECRET_DATA", "password": "s3cr3t"})
    );
}

#[tokio::test]
async fn creates_shared_metadata_when_personal_keys_are_not_allowed() {
    let fake = v5_server(
        json!({"allow_usage_of_personal_keys": false, "zero_knowledge_key_share": false}),
    );

    let body = create(&fake, &github()).await.unwrap();

    assert_eq!(body["metadata_key_type"], "shared_key");
    assert_eq!(body["metadata_key_id"], "mk1");
    let metadata = METADATA.decrypt_signed(body["metadata"].as_str().unwrap(), &[&METADATA, &ADA]);
    assert!(metadata.contains(r#""name":"GitHub""#), "{metadata}");
}

#[rstest]
#[case::password_and_totp(NewResource { totp: Some(totp()), ..github() }, "v5-default-with-totp")]
#[case::totp(NewResource { totp: Some(totp()), password: None, username: None, ..github() }, "v5-totp-standalone")]
#[case::pin_code(NewResource { pin_code: Some("1234".into()), ..NewResource { name: "Door".into(), ..NewResource::default() } }, "v5-pin-code")]
#[case::note(NewResource { note: Some("secret note".into()), ..NewResource { name: "Note".into(), ..NewResource::default() } }, "v5-note")]
#[tokio::test]
async fn picks_the_v5_type_matching_the_secret(
    #[case] new_resource: NewResource,
    #[case] slug: &str,
) {
    let fake = v5_server(data::metadata_keys_settings());

    let body = create(&fake, &new_resource).await.unwrap();

    assert_eq!(body["resource_type_id"], data::resource_type_id(slug));
}

#[tokio::test]
async fn splits_custom_fields_between_metadata_and_secret() {
    let fake = v5_server(data::metadata_keys_settings());
    let new_resource = NewResource {
        name: "Account".into(),
        custom_fields: vec![CustomField {
            id: CUSTOM_FIELD_ID.into(),
            field_type: "text".into(),
            metadata_key: Some("Account number".into()),
            metadata_value: None,
            secret_key: None,
            secret_value: Some("42".into()),
        }],
        ..NewResource::default()
    };

    let body = create(&fake, &new_resource).await.unwrap();

    assert_eq!(
        body["resource_type_id"],
        data::resource_type_id("v5-custom-fields")
    );
    let metadata = ADA.decrypt_json(body["metadata"].as_str().unwrap());
    assert_eq!(
        metadata["custom_fields"],
        json!([{"id": CUSTOM_FIELD_ID, "type": "text", "metadata_key": "Account number"}])
    );
    assert_eq!(
        ada_secret(&body)["custom_fields"],
        json!([{"id": CUSTOM_FIELD_ID, "type": "text", "secret_value": "42"}])
    );
}

#[tokio::test]
async fn creates_a_v4_type_when_asked() {
    let fake = v5_server(data::metadata_keys_settings());

    let body = create(
        &fake,
        &NewResource {
            resource_type: Some("password-string".into()),
            description: None,
            ..github()
        },
    )
    .await
    .unwrap();

    assert_eq!(body["name"], "GitHub");
    assert_eq!(body["uri"], "https://github.com");
    assert!(body.get("metadata").is_none());
    assert_eq!(
        ADA.decrypt_signed(secret_of(&body, ADA_ID), &[&ADA]),
        "s3cr3t"
    );
}

#[rstest]
#[case::read_only_type(NewResource { resource_type: Some("v5-password-string".into()), ..github() }, "read-only")]
#[case::unknown_type(NewResource { resource_type: Some("v5-unknown".into()), ..github() }, "Unknown resource type")]
#[case::field_of_another_type(NewResource { resource_type: Some("v5-totp-standalone".into()), password: None, totp: Some(totp()), ..github() }, "username is not allowed")]
#[case::invalid_pin_code(NewResource { pin_code: Some("12ab".into()), ..NewResource { name: "Door".into(), ..NewResource::default() } }, "pin_code does not match")]
#[case::two_uris_on_v4(NewResource { resource_type: Some("password-and-description".into()), uris: vec!["a".into(), "b".into()], ..github() }, "single URI")]
#[case::nothing_secret(NewResource { password: None, ..github() }, "Nothing to keep secret")]
#[tokio::test]
async fn refuses_what_the_type_does_not_allow(
    #[case] new_resource: NewResource,
    #[case] expected: &str,
) {
    let fake = v5_server(data::metadata_keys_settings());

    let error = refused(&fake, &new_resource).await;

    assert!(error.contains(expected), "{error}");
}

#[tokio::test]
async fn refuses_v5_when_the_server_settings_forbid_it() {
    let fake = v5_server(data::metadata_keys_settings());
    let mut types_settings = data::metadata_types_settings();
    types_settings["allow_creation_of_v5_resources"] = false.into();
    fake.with_metadata_settings(types_settings, data::metadata_keys_settings());

    let error = refused(
        &fake,
        &NewResource {
            resource_type: Some("v5-default".into()),
            ..github()
        },
    )
    .await;

    assert!(error.contains("do not allow creating v5"), "{error}");
}

#[tokio::test]
async fn creates_v4_without_the_metadata_plugin() {
    let fake = FakePassbolt::new();
    fake.with_directory();
    fake.on(
        "POST",
        "/resources.json",
        data::resource_v4("password-and-description", "{}"),
    );

    let body = create(&fake, &github()).await.unwrap();

    assert_eq!(
        body["resource_type_id"],
        data::resource_type_id("password-and-description")
    );
    assert_eq!(body["name"], "GitHub");
}

fn shared_keys_server(keys: Value) -> FakePassbolt {
    let fake = v5_server(
        json!({"allow_usage_of_personal_keys": false, "zero_knowledge_key_share": false}),
    );
    fake.on("GET", "/metadata/keys.json", keys);
    fake
}

/// `mk-old` created before `mk-new`, both shared with ada.
fn two_metadata_keys() -> Value {
    let mut keys = data::metadata_keys(&[("mk-old", &METADATA), ("mk-new", &METADATA)]);
    keys[0]["created"] = "2025-01-01T00:00:00+00:00".into();
    keys[1]["created"] = "2025-06-01T00:00:00+00:00".into();
    keys
}

#[tokio::test]
async fn metadata_holds_only_the_fields_of_its_type() {
    let fake = v5_server(data::metadata_keys_settings());
    let pin = NewResource {
        pin_code: Some("1234".into()),
        ..NewResource {
            name: "Door".into(),
            ..NewResource::default()
        }
    };

    let body = create(&fake, &pin).await.unwrap();

    let metadata = ADA.decrypt_json(body["metadata"].as_str().unwrap());
    let mut fields: Vec<&str> = metadata
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(fields, ["name", "object_type", "resource_type_id"]);
}

#[tokio::test]
async fn new_shared_metadata_uses_the_latest_created_key() {
    let fake = shared_keys_server(two_metadata_keys());

    let body = create(&fake, &github()).await.unwrap();

    assert_eq!(body["metadata_key_id"], "mk-new");
}

#[tokio::test]
async fn an_expired_key_is_not_used_for_new_metadata() {
    let mut keys = two_metadata_keys();
    keys[1]["expired"] = "2025-07-01T00:00:00+00:00".into();
    let fake = shared_keys_server(keys);

    let body = create(&fake, &github()).await.unwrap();

    assert_eq!(body["metadata_key_id"], "mk-old");
}

#[tokio::test]
async fn shared_metadata_needs_an_active_key() {
    let mut keys = two_metadata_keys();
    for key in keys.as_array_mut().unwrap() {
        key["expired"] = "2025-07-01T00:00:00+00:00".into();
    }
    let fake = shared_keys_server(keys);

    let error = create(&fake, &github()).await.unwrap_err();

    assert!(
        error.to_string().contains("no active shared metadata key"),
        "{error}"
    );
}

#[tokio::test]
async fn without_a_share_of_the_key_metadata_is_signed_by_the_user_only() {
    let mut keys = data::metadata_keys(&[("mk1", &METADATA)]);
    keys[0]["metadata_private_keys"] = json!([]);
    let fake = shared_keys_server(keys);

    let body = create(&fake, &github()).await.unwrap();

    let metadata = METADATA.decrypt_signed(body["metadata"].as_str().unwrap(), &[&ADA]);
    assert!(metadata.contains(r#""name":"GitHub""#), "{metadata}");
}

#[tokio::test]
async fn settings_and_resource_types_are_fetched_once() {
    let fake = v5_server(data::metadata_keys_settings());
    let client = login_ada(&fake).await;

    for _ in 0..2 {
        create::create_resource(&client, &github()).await.unwrap();
    }

    for path in [
        "/metadata/types/settings.json",
        "/metadata/keys/settings.json",
        "/resource-types.json",
    ] {
        assert_eq!(fake.requests_to("GET", path).len(), 1, "{path}");
    }
}

#[tokio::test]
async fn a_settings_error_other_than_missing_plugin_is_reported() {
    let fake = v5_server(data::metadata_keys_settings());
    fake.on_error_saying(
        "GET",
        "/metadata/types/settings.json",
        500,
        "Internal error.",
    );
    let client = login_ada(&fake).await;

    let error = create::create_resource(&client, &github())
        .await
        .unwrap_err();

    assert!(
        matches!(
            error,
            PassboltError::Api(passbolt_sdk::ApiError { status: 500, .. })
        ),
        "{error:?}"
    );
}

#[tokio::test]
async fn free_fields_are_written_last_and_checked() {
    let fake = v5_server(data::metadata_keys_settings());
    let mut new_resource = github();
    new_resource
        .metadata_fields
        .insert("username".into(), "from-field".into());

    let body = create(&fake, &new_resource).await.unwrap();

    assert_eq!(
        ADA.decrypt_json(body["metadata"].as_str().unwrap())["username"],
        "from-field"
    );
}

#[rstest]
#[case::secret_field_on_a_password_string(
    NewResource { resource_type: Some("password-string".into()), description: None, secret_fields: serde_json::Map::from_iter([("totp".to_string(), json!({}))]), ..github() },
    "totp is not allowed"
)]
#[case::undeclared_metadata_field(
    NewResource { metadata_fields: serde_json::Map::from_iter([("colour".to_string(), json!("red"))]), ..github() },
    "colour is not allowed"
)]
#[case::note_on_v4(NewResource { resource_type: Some("password-and-description".into()), description: None, note: Some("n".into()), ..github() }, "secret description of v5")]
#[tokio::test]
async fn free_fields_and_notes_follow_the_type(
    #[case] new_resource: NewResource,
    #[case] expected: &str,
) {
    let fake = v5_server(data::metadata_keys_settings());

    let error = refused(&fake, &new_resource).await;

    assert!(error.contains(expected), "{error}");
}

async fn create_with_pinned_metadata_key(
    fake: &FakePassbolt,
    fingerprint: &str,
) -> Result<Value, PassboltError> {
    let mut config = ada_config();
    config.metadata_key_fingerprint = fingerprint.into();
    let client = passbolt_sdk::PassboltSdk::login(fake.clone(), &config, None, 3)
        .await
        .unwrap();
    create::create_resource(&client, &github()).await?;
    Ok(fake.body_of("POST", "/resources.json"))
}

#[tokio::test]
async fn shared_metadata_is_encrypted_for_the_pinned_key() {
    let fake = shared_keys_server(data::metadata_keys(&[("mk1", &METADATA)]));

    let body = create_with_pinned_metadata_key(&fake, &METADATA.fingerprint().to_lowercase())
        .await
        .unwrap();

    assert_eq!(body["metadata_key_id"], "mk1");
}

#[tokio::test]
async fn shared_metadata_is_not_encrypted_for_another_key_than_the_pinned_one() {
    let fake = shared_keys_server(data::metadata_keys(&[("mk1", &METADATA)]));

    let error = create_with_pinned_metadata_key(&fake, &SERVER.fingerprint())
        .await
        .unwrap_err();

    assert!(
        matches!(&error, PassboltError::Crypto(passbolt_sdk::CryptoError::UntrustedMetadataKey { active, .. })
            if *active == METADATA.fingerprint()),
        "{error:?}"
    );
    assert!(fake.requests_to("POST", "/resources.json").is_empty());
}
