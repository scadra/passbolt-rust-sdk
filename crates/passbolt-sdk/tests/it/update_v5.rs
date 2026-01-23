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

use passbolt_sdk::resource::update::{self, ResourceChanges};
use passbolt_sdk::types::TotpData;
use passbolt_sdk::PassboltError;
use serde_json::{json, Value};

use crate::common::*;

const ADA_GPGKEY_ID: &str = "8b6c3a10-0000-4000-8000-000000008888";

/// Ada's personal v5-default resource, shared with betty for the secret.
fn personal_resource(slug: &str, secret: &Value) -> FakePassbolt {
    serving(data::resource_v5_with_secret(
        slug,
        &data::metadata("GitHub"),
        (&ADA, "user_key", ADA_GPGKEY_ID),
        &secret.to_string(),
    ))
}

fn serving(resource: Value) -> FakePassbolt {
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
    fake.on("GET", &resource_path(), resource.clone());
    fake.on("GET", "/users.json", data::users(&["ada", "betty"]));
    fake.on("PUT", &resource_path(), resource);
    fake
}

async fn update(fake: &FakePassbolt, changes: ResourceChanges) -> Result<Value, PassboltError> {
    let client = login_ada(fake).await;
    update::update_resource(&client, RESOURCE_ID, &changes).await?;
    Ok(fake.body_of("PUT", &resource_path()))
}

fn metadata_for(key: &keys::TestKey, body: &Value) -> Value {
    key.decrypt_json(body["metadata"].as_str().unwrap())
}

fn v5_secret() -> Value {
    data::secret_v5_default()
}

#[tokio::test]
async fn a_new_password_is_encrypted_for_everyone_with_access_and_keeps_the_metadata() {
    let fake = personal_resource("v5-default", &v5_secret());

    let body = update(
        &fake,
        ResourceChanges {
            password: Some("new".into()),
            ..ResourceChanges::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(
        body["resource_type_id"],
        data::resource_type_id("v5-default")
    );
    assert_eq!(body["metadata_key_type"], "user_key");
    assert_eq!(body["metadata_key_id"], ADA_GPGKEY_ID);
    let mut expected_metadata = data::metadata("GitHub");
    expected_metadata["resource_type_id"] = data::resource_type_id("v5-default").into();
    assert_eq!(metadata_for(&ADA, &body), expected_metadata);
    let mut expected_secret = v5_secret();
    expected_secret["password"] = "new".into();
    for (key, user_id) in [(&ADA, ADA_ID), (&BETTY, BETTY_ID)] {
        let secret: Value =
            serde_json::from_str(&key.decrypt_signed(secret_of(&body, user_id), &[&ADA])).unwrap();
        assert_eq!(secret, expected_secret);
    }
    for clear_field in ["name", "username", "uri", "description"] {
        assert!(
            body.get(clear_field).is_none(),
            "{clear_field} sent in clear"
        );
    }
}

#[tokio::test]
async fn a_new_name_changes_the_metadata_only() {
    let fake = personal_resource("v5-default", &v5_secret());

    let body = update(
        &fake,
        ResourceChanges {
            name: Some("GitLab".into()),
            ..ResourceChanges::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(metadata_for(&ADA, &body)["name"], "GitLab");
    assert!(body.get("secrets").is_none(), "{body}");
}

#[tokio::test]
async fn the_description_goes_to_the_metadata_and_the_note_to_the_secret() {
    let fake = personal_resource("v5-default", &v5_secret());

    let body = update(
        &fake,
        ResourceChanges {
            description: Some("public".into()),
            note: Some("private".into()),
            ..ResourceChanges::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(metadata_for(&ADA, &body)["description"], "public");
    assert_eq!(
        ADA.decrypt_json(secret_of(&body, ADA_ID))["description"],
        "private"
    );
}

#[tokio::test]
async fn shared_metadata_is_encrypted_again_for_the_shared_key() {
    let fake = serving(data::resource_v5_with_secret(
        "v5-default",
        &data::metadata("GitHub"),
        (&METADATA, "shared_key", "mk1"),
        &v5_secret().to_string(),
    ));

    let body = update(
        &fake,
        ResourceChanges {
            name: Some("GitLab".into()),
            ..ResourceChanges::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(body["metadata_key_type"], "shared_key");
    assert_eq!(body["metadata_key_id"], "mk1");
    let metadata = METADATA.decrypt_signed(body["metadata"].as_str().unwrap(), &[&METADATA, &ADA]);
    assert!(metadata.contains(r#""name":"GitLab""#), "{metadata}");
}

#[tokio::test]
async fn adding_a_totp_switches_to_the_type_with_totp() {
    let fake = personal_resource("v5-default", &v5_secret());

    let body = update(
        &fake,
        ResourceChanges {
            totp: Some(TotpData {
                secret_key: Some("JBSWY3DPEHPK3PXP".into()),
                ..TotpData::default()
            }),
            ..ResourceChanges::default()
        },
    )
    .await
    .unwrap();

    let with_totp = data::resource_type_id("v5-default-with-totp");
    assert_eq!(body["resource_type_id"], with_totp);
    assert_eq!(metadata_for(&ADA, &body)["resource_type_id"], with_totp);
    assert_eq!(
        ADA.decrypt_json(secret_of(&body, ADA_ID))["totp"],
        json!({"algorithm": "SHA1", "digits": 6, "period": 30, "secret_key": "JBSWY3DPEHPK3PXP"})
    );
}

#[tokio::test]
async fn removing_the_only_secret_is_refused() {
    let fake = personal_resource(
        "v5-totp-standalone",
        &json!({"object_type": "PASSBOLT_SECRET_DATA", "totp": {"secret_key": "K", "digits": 6, "algorithm": "SHA1", "period": 30}}),
    );

    let error = update(
        &fake,
        ResourceChanges {
            remove_totp: true,
            ..ResourceChanges::default()
        },
    )
    .await
    .unwrap_err();

    assert!(
        error.to_string().contains("delete the resource instead"),
        "{error}"
    );
    assert!(fake.requests_to("PUT", &resource_path()).is_empty());
}

#[tokio::test]
async fn a_pin_code_is_checked_against_the_type() {
    let fake = personal_resource(
        "v5-pin-code",
        &json!({"object_type": "PASSBOLT_SECRET_DATA", "pin_code": "1234"}),
    );

    let error = update(
        &fake,
        ResourceChanges {
            pin_code: Some("12ab".into()),
            ..ResourceChanges::default()
        },
    )
    .await
    .unwrap_err();

    assert!(
        error.to_string().contains("pin_code does not match"),
        "{error}"
    );
}

#[tokio::test]
async fn a_v4_update_keeps_the_resource_type() {
    let fake = fake_serving_resource("password-string", "p", ada_owner_permissions());
    fake.on(
        "PUT",
        &resource_path(),
        data::resource_v4("password-string", "p"),
    );

    let body = update(
        &fake,
        ResourceChanges {
            name: Some("GitLab".into()),
            ..ResourceChanges::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(
        body["resource_type_id"],
        data::resource_type_id("password-string")
    );
    assert_eq!(body["name"], "GitLab");
}

fn changes() -> ResourceChanges {
    ResourceChanges::default()
}

#[rstest::rstest]
#[case::remove_from_default_with_totp("v5-default-with-totp", true, Some("v5-default"))]
#[case::add_to_password_string("v5-password-string", false, Some("v5-default-with-totp"))]
#[case::add_to_a_note("v5-note", false, None)]
#[case::remove_without_totp("v5-default", true, None)]
#[tokio::test]
async fn totp_changes_switch_the_type_or_are_refused(
    #[case] slug: &str,
    #[case] remove: bool,
    #[case] expected_slug: Option<&str>,
) {
    let secret = match slug {
        "v5-password-string" => json!("p"),
        "v5-note" => json!({"object_type": "PASSBOLT_SECRET_DATA", "description": "n"}),
        "v5-default-with-totp" => json!({"object_type": "PASSBOLT_SECRET_DATA", "password": "p",
            "totp": {"secret_key": "K", "digits": 6, "algorithm": "SHA1", "period": 30}}),
        _ => v5_secret(),
    };
    let secret = secret
        .as_str()
        .map_or_else(|| secret.to_string(), String::from);
    let fake = serving(data::resource_v5_with_secret(
        slug,
        &data::metadata("GitHub"),
        (&ADA, "user_key", ADA_GPGKEY_ID),
        &secret,
    ));
    let totp = (!remove).then(|| TotpData {
        secret_key: Some("JBSWY3DPEHPK3PXP".into()),
        ..TotpData::default()
    });

    let result = update(
        &fake,
        ResourceChanges {
            totp,
            remove_totp: remove,
            ..changes()
        },
    )
    .await;

    match expected_slug {
        Some(expected) => assert_eq!(
            result.unwrap()["resource_type_id"],
            data::resource_type_id(expected)
        ),
        None => assert!(
            matches!(result, Err(PassboltError::InvalidArgument(_))),
            "{result:?}"
        ),
    }
}

#[tokio::test]
async fn a_v5_password_string_stays_a_string() {
    let fake = serving(data::resource_v5_with_secret(
        "v5-password-string",
        &data::metadata("GitHub"),
        (&ADA, "user_key", ADA_GPGKEY_ID),
        "old",
    ));

    let body = update(
        &fake,
        ResourceChanges {
            password: Some("new".into()),
            ..changes()
        },
    )
    .await
    .unwrap();

    assert_eq!(ADA.decrypt(secret_of(&body, ADA_ID)), "new");
}

#[tokio::test]
async fn unknown_metadata_fields_are_kept() {
    let mut metadata = data::metadata("GitHub");
    metadata["field_from_a_newer_client"] = json!({"kept": true});
    let fake = serving(data::resource_v5_with_secret(
        "v5-default",
        &metadata,
        (&ADA, "user_key", ADA_GPGKEY_ID),
        &v5_secret().to_string(),
    ));

    let body = update(
        &fake,
        ResourceChanges {
            name: Some("GitLab".into()),
            ..changes()
        },
    )
    .await
    .unwrap();

    assert_eq!(
        metadata_for(&ADA, &body)["field_from_a_newer_client"],
        json!({"kept": true})
    );
}

#[tokio::test]
async fn clearing_the_expiry_sends_null() {
    let fake = personal_resource("v5-default", &v5_secret());

    let body = update(
        &fake,
        ResourceChanges {
            expired: Some(None),
            ..changes()
        },
    )
    .await
    .unwrap();

    assert_eq!(body.get("expired"), Some(&Value::Null));
}

#[tokio::test]
async fn a_resource_of_an_unknown_type_is_not_updated() {
    let mut resource = data::resource_v4("password-string", "p");
    resource["resource_type_id"] = "00000000-0000-4000-8000-0000000000aa".into();
    let fake = FakePassbolt::new();
    fake.on("GET", &resource_path(), resource);

    let error = update(
        &fake,
        ResourceChanges {
            name: Some("x".into()),
            ..changes()
        },
    )
    .await
    .unwrap_err();

    assert!(
        error.to_string().contains("Unknown resource type"),
        "{error}"
    );
    assert!(fake.requests_to("PUT", &resource_path()).is_empty());
}

#[tokio::test]
async fn clearing_a_v4_uri_sends_null() {
    let mut resource = data::resource_v4("password-and-description", r#"{"password":"p"}"#);
    resource["uri"] = "https://old.test".into();
    let fake = FakePassbolt::new();
    fake.on("GET", &resource_path(), resource.clone());
    fake.on("PUT", &resource_path(), resource);

    let body = update(
        &fake,
        ResourceChanges {
            uris: Some(vec![]),
            ..changes()
        },
    )
    .await
    .unwrap();

    assert_eq!(body.get("uri"), Some(&Value::Null), "{body}");
}

#[tokio::test]
async fn a_note_is_refused_on_a_v4_type() {
    let fake = fake_serving_resource(
        "password-and-description",
        r#"{"password":"p"}"#,
        ada_owner_permissions(),
    );

    let error = update(
        &fake,
        ResourceChanges {
            note: Some("n".into()),
            ..changes()
        },
    )
    .await
    .unwrap_err();

    assert!(
        error.to_string().contains("secret description of v5"),
        "{error}"
    );
}

#[tokio::test]
async fn a_secret_field_is_refused_on_a_password_string() {
    let fake = fake_serving_resource("password-string", "p", ada_owner_permissions());
    let secret_fields = serde_json::Map::from_iter([("pin_code".to_string(), json!("1234"))]);

    let error = update(
        &fake,
        ResourceChanges {
            secret_fields,
            ..changes()
        },
    )
    .await
    .unwrap_err();

    assert!(
        error.to_string().contains("pin_code is not allowed"),
        "{error}"
    );
}

#[tokio::test]
async fn personal_metadata_goes_to_the_shared_key_once_personal_keys_are_disallowed() {
    let fake = personal_resource("v5-default", &v5_secret());
    fake.with_metadata_settings(
        data::metadata_types_settings(),
        json!({"allow_usage_of_personal_keys": false, "zero_knowledge_key_share": false}),
    );

    let body = update(
        &fake,
        ResourceChanges {
            name: Some("GitLab".into()),
            ..ResourceChanges::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(body["metadata_key_type"], "shared_key");
    assert_eq!(metadata_for(&METADATA, &body)["name"], "GitLab");
}

#[tokio::test]
async fn shared_metadata_of_a_resource_only_the_user_reads_becomes_personal() {
    let mut resource = data::resource_v5_with_secret(
        "v5-default",
        &data::metadata("GitHub"),
        (&METADATA, "shared_key", "mk1"),
        &v5_secret().to_string(),
    );
    // Its other permissions were revoked: the server marks it personal again.
    resource["personal"] = true.into();
    let fake = serving(resource);

    let body = update(
        &fake,
        ResourceChanges {
            name: Some("GitLab".into()),
            ..ResourceChanges::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(body["metadata_key_type"], "user_key");
    assert_eq!(body["metadata_key_id"], ADA_GPGKEY_ID);
    assert_eq!(metadata_for(&ADA, &body)["name"], "GitLab");
}
