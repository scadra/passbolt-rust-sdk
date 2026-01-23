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

use std::collections::BTreeSet;

use passbolt_sdk::group::{create as group_create, update as group_update};
use passbolt_sdk::resource::share;
use passbolt_sdk::user::{create as user_create, update as user_update};
use passbolt_sdk::PassboltError;
use serde_json::{json, Value};

use crate::common::*;

fn share_path() -> String {
    format!("/share/resource/{RESOURCE_ID}.json")
}

fn group_path() -> String {
    format!("/groups/{GROUP_ID}.json")
}

fn fake_serving_shareable_resource(secret: &str, permissions: Value) -> FakePassbolt {
    let fake = fake_serving_resource("password-and-description", secret, permissions);
    fake.on("PUT", &share_path(), Value::Null);
    fake
}

fn fake_serving_group() -> FakePassbolt {
    let fake = FakePassbolt::new();
    fake.with_directory();
    fake.on("GET", &group_path(), data::group());
    fake.on("PUT", &group_path(), data::group());
    fake
}

fn ada_owner_betty_reader_permissions() -> Value {
    json!([
        data::permission("p-ada", "User", ADA_ID, 15),
        data::permission("p-betty", "User", BETTY_ID, 1)
    ])
}

async fn share_with(
    client: &Client,
    user_ids: &[&str],
    group_ids: &[&str],
    permission_type: i32,
) -> Result<(), PassboltError> {
    let user_ids: Vec<String> = user_ids
        .iter()
        .map(|user_id| (*user_id).to_string())
        .collect();
    let group_ids: Vec<String> = group_ids
        .iter()
        .map(|group_id| (*group_id).to_string())
        .collect();
    share::share_resource(client, RESOURCE_ID, &user_ids, &group_ids, permission_type).await
}

#[tokio::test]
async fn share_with_a_user_adds_a_permission_and_their_secret() {
    let fake = fake_serving_shareable_resource(
        r#"{"password":"p","description":"d"}"#,
        ada_owner_permissions(),
    );
    let client = login_ada(&fake).await;

    share_with(&client, &[BETTY_ID], &[], 7).await.unwrap();

    let body = fake.body_of("PUT", &share_path());
    assert_eq!(
        body["permissions"],
        json!([{ "aro": "User", "aro_foreign_key": BETTY_ID, "type": 7 }])
    );
    assert_eq!(secret_user_ids(&body), BTreeSet::from([BETTY_ID]));
    let betty_secret = BETTY.decrypt_json(secret_of(&body, BETTY_ID));
    assert_eq!(
        (&betty_secret["password"], &betty_secret["description"]),
        (&json!("p"), &json!("d"))
    );
}

#[tokio::test]
async fn revoke_deletes_the_existing_permission_without_secrets() {
    let fake = fake_serving_shareable_resource(
        r#"{"password":"p"}"#,
        ada_owner_betty_reader_permissions(),
    );
    let client = login_ada(&fake).await;

    share_with(&client, &[BETTY_ID], &[], -1).await.unwrap();

    let body = fake.body_of("PUT", &share_path());
    assert_eq!(
        body["permissions"],
        json!([{ "id": "p-betty", "aro": "User", "aro_foreign_key": BETTY_ID, "delete": true }])
    );
    assert!(body.get("secrets").is_none());
}

#[tokio::test]
async fn revoke_without_matching_permission_fails_before_sharing() {
    let fake = fake_serving_shareable_resource(r#"{"password":"p"}"#, ada_owner_permissions());
    let client = login_ada(&fake).await;

    let error = share_with(&client, &[BETTY_ID], &[], -1).await.unwrap_err();

    assert!(
        matches!(error, PassboltError::InvalidArgument(_)),
        "{error:?}"
    );
    assert!(fake.requests_to("PUT", &share_path()).is_empty());
}

#[tokio::test]
async fn create_group_lists_managers_first_without_duplicates() {
    let fake = FakePassbolt::new();
    fake.on("POST", "/groups.json", data::group());
    let client = login_ada(&fake).await;

    group_create::create_group(
        &client,
        "Ops",
        &[ADA_ID.into(), BETTY_ID.into()],
        &[ADA_ID.into()],
    )
    .await
    .unwrap();

    assert_eq!(
        fake.body_of("POST", "/groups.json")["groups_users"],
        json!([{ "user_id": ADA_ID, "is_admin": true }, { "user_id": BETTY_ID, "is_admin": false }])
    );
}

#[tokio::test]
async fn create_user_resolves_the_role_name() {
    let fake = FakePassbolt::new();
    fake.with_directory();
    fake.on("POST", "/users.json", data::user("betty"));
    let client = login_ada(&fake).await;

    user_create::create_user(&client, "betty@passbolt.test", "Betty", "Test", "admin")
        .await
        .unwrap();

    assert_eq!(
        fake.body_of("POST", "/users.json")["role_id"],
        data::role_id("admin")
    );
}

#[tokio::test]
async fn create_user_with_an_unknown_role_fails_before_posting() {
    let fake = FakePassbolt::new();
    fake.with_directory();
    let client = login_ada(&fake).await;

    let error = user_create::create_user(&client, "x@passbolt.test", "X", "Y", "superuser")
        .await
        .unwrap_err();

    assert!(matches!(error, PassboltError::NotFound(_)), "{error:?}");
    assert!(fake.requests_to("POST", "/users.json").is_empty());
}

#[tokio::test]
async fn share_with_a_group_encrypts_for_the_members_who_gain_access() {
    let fake = fake_serving_shareable_resource(r#"{"password":"p"}"#, ada_owner_permissions());
    let client = login_ada(&fake).await;

    share_with(&client, &[], &[GROUP_ID], 1).await.unwrap();

    // Ada, the other member, already has access.
    assert_eq!(
        secret_user_ids(&fake.body_of("PUT", &share_path())),
        BTreeSet::from([BETTY_ID])
    );
}

#[tokio::test]
async fn share_updates_an_existing_permission() {
    let fake = fake_serving_shareable_resource(
        r#"{"password":"p"}"#,
        ada_owner_betty_reader_permissions(),
    );
    let client = login_ada(&fake).await;

    share_with(&client, &[BETTY_ID], &[], 15).await.unwrap();

    let body = fake.body_of("PUT", &share_path());
    assert_eq!(
        body["permissions"],
        json!([{ "id": "p-betty", "aro": "User", "aro_foreign_key": BETTY_ID, "type": 15 }])
    );
    assert!(
        body.get("secrets").is_none(),
        "betty already has the secret"
    );
}

#[tokio::test]
async fn share_keeps_the_secret_unchanged() {
    let fake = fake_serving_resource("password-string", "raw-password", ada_owner_permissions());
    fake.on("PUT", &share_path(), Value::Null);
    let client = login_ada(&fake).await;

    share_with(&client, &[BETTY_ID], &[], 1).await.unwrap();

    assert_eq!(
        BETTY.decrypt(secret_of(&fake.body_of("PUT", &share_path()), BETTY_ID)),
        "raw-password"
    );
}

#[tokio::test]
async fn adding_a_group_member_sends_the_needed_secrets() {
    let fake = fake_serving_group();
    fake.on(
        "PUT",
        &format!("/groups/{GROUP_ID}/dry-run.json"),
        data::group_dry_run("p"),
    );
    let client = login_ada(&fake).await;

    group_update::update_group(&client, GROUP_ID, None, &[CAROL_ID.into()], &[], &[])
        .await
        .unwrap();

    assert_eq!(
        CAROL.decrypt(secret_of(&fake.body_of("PUT", &group_path()), CAROL_ID)),
        "p"
    );
}

#[tokio::test]
async fn removing_a_group_member_uses_the_membership_id() {
    let fake = fake_serving_group();
    let client = login_ada(&fake).await;

    group_update::update_group(&client, GROUP_ID, None, &[], &[], &[BETTY_ID.into()])
        .await
        .unwrap();

    assert_eq!(
        fake.body_of("PUT", &group_path())["groups_users"],
        json!([{ "id": data::group_membership_id(BETTY_ID), "delete": true }])
    );
}

#[tokio::test]
async fn update_user_resolves_the_role_name() {
    let fake = FakePassbolt::new();
    fake.with_directory();
    fake.on(
        "PUT",
        &format!("/users/{BETTY_ID}.json"),
        data::user("betty"),
    );
    let client = login_ada(&fake).await;

    user_update::update_user(&client, BETTY_ID, None, None, Some("admin"))
        .await
        .unwrap();

    assert_eq!(
        fake.body_of("PUT", &format!("/users/{BETTY_ID}.json"))["role_id"],
        data::role_id("admin")
    );
}

#[tokio::test]
async fn sharing_personal_v5_metadata_moves_it_to_the_shared_key_first() {
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
    let resource = data::resource_v5_with_secret(
        "v5-default",
        &data::metadata("GitHub"),
        (&ADA, "user_key", "8b6c3a10-0000-4000-8000-000000008888"),
        r#"{"object_type":"PASSBOLT_SECRET_DATA","password":"p"}"#,
    );
    fake.on("GET", &resource_path(), resource.clone());
    fake.on("PUT", &resource_path(), resource);
    fake.on(
        "GET",
        &format!("/permissions/resource/{RESOURCE_ID}.json"),
        ada_owner_permissions(),
    );
    fake.on("PUT", &share_path(), Value::Null);
    let client = login_ada(&fake).await;

    share_with(&client, &[BETTY_ID], &[], 1).await.unwrap();

    let update = fake.body_of("PUT", &resource_path());
    assert_eq!(
        (&update["metadata_key_type"], &update["metadata_key_id"]),
        (&json!("shared_key"), &json!("mk1"))
    );
    assert!(METADATA
        .decrypt(update["metadata"].as_str().unwrap())
        .contains(r#""name":"GitHub""#));
    assert_eq!(
        secret_user_ids(&fake.body_of("PUT", &share_path())),
        BTreeSet::from([BETTY_ID])
    );
}

fn move_path() -> String {
    format!("/move/resource/{RESOURCE_ID}.json")
}

/// The resource in `FOLDER_ID` with `permissions`, ada's own being `ada_permission_type`, and
/// `destination` holding `destination_permissions`.
fn fake_moving_resource(
    permissions: Value,
    ada_permission_type: i32,
    destination: &str,
    destination_permissions: Value,
) -> FakePassbolt {
    let fake = fake_serving_shareable_resource(r#"{"password":"p"}"#, permissions);
    let mut resource = data::resource_v4("password-and-description", r#"{"password":"p"}"#);
    resource["folder_parent_id"] = FOLDER_ID.into();
    resource["permission"] = data::permission("p-ada", "User", ADA_ID, ada_permission_type);
    fake.on("GET", &resource_path(), resource);
    fake.on(
        "GET",
        &format!("/folders/{FOLDER_ID}.json"),
        data::folder(json!([
            data::permission("f-ada", "User", ADA_ID, 15),
            data::permission("f-betty", "User", BETTY_ID, 1)
        ])),
    );
    fake.on(
        "GET",
        &format!("/folders/{destination}.json"),
        data::folder(destination_permissions),
    );
    fake.on("PUT", &move_path(), Value::Null);
    fake
}

async fn move_into(fake: &FakePassbolt, destination: &str) -> Result<(), PassboltError> {
    let client = login_ada(fake).await;
    share::move_with_folder_permissions(&client, RESOURCE_ID, Some(destination)).await
}

#[tokio::test]
async fn moving_trades_the_old_folder_permissions_for_the_destination_ones() {
    let fake = fake_moving_resource(
        ada_owner_betty_reader_permissions(),
        15,
        CHILD_FOLDER_ID,
        json!([
            data::permission("d-ada", "User", ADA_ID, 15),
            data::permission("d-carol", "User", CAROL_ID, 7)
        ]),
    );

    move_into(&fake, CHILD_FOLDER_ID).await.unwrap();

    assert_eq!(
        fake.body_of("PUT", &move_path())["folder_parent_id"],
        CHILD_FOLDER_ID
    );
    let body = fake.body_of("PUT", &share_path());
    assert_eq!(
        body["permissions"],
        json!([
            { "aro": "User", "aro_foreign_key": CAROL_ID, "type": 7 },
            { "id": "p-betty", "aro": "User", "aro_foreign_key": BETTY_ID, "delete": true }
        ])
    );
}

#[tokio::test]
async fn moving_is_refused_before_anything_moves_for_a_non_owner() {
    let fake = fake_moving_resource(ada_owner_permissions(), 7, CHILD_FOLDER_ID, json!([]));

    let error = move_into(&fake, CHILD_FOLDER_ID).await.unwrap_err();

    assert!(error.to_string().contains("Only an owner"), "{error}");
    assert!(fake.requests_to("PUT", &move_path()).is_empty());
}

#[tokio::test]
async fn a_move_leaving_no_owner_is_refused_before_anything_moves() {
    // Ada only owns the resource through the folder it leaves.
    let fake = fake_moving_resource(
        json!([data::permission("p-ada", "User", ADA_ID, 15)]),
        15,
        CHILD_FOLDER_ID,
        json!([data::permission("d-betty", "User", BETTY_ID, 7)]),
    );
    fake.on(
        "GET",
        &format!("/folders/{FOLDER_ID}.json"),
        data::folder(json!([data::permission("f-ada", "User", ADA_ID, 15)])),
    );

    let error = move_into(&fake, CHILD_FOLDER_ID).await.unwrap_err();

    assert!(error.to_string().contains("without owner"), "{error}");
    assert!(fake.requests_to("PUT", &move_path()).is_empty());
}

const CHILD_FOLDER_ID: &str = "5f6e7d8c-0000-4000-8000-0000000000f2";
const FOREIGN_FOLDER_ID: &str = "5f6e7d8c-0000-4000-8000-0000000000f3";

fn folder_share_path(id: &str) -> String {
    format!("/share/folder/{id}.json")
}

/// A folder `id` in `parent`, ada's own permission of `ada_permission_type`.
fn folder_in(id: &str, parent: Option<&str>, ada_permission_type: i32) -> Value {
    let ada = data::permission(&format!("{id}-ada"), "User", ADA_ID, ada_permission_type);
    let mut folder = data::folder(json!([ada]));
    folder["id"] = id.into();
    folder["folder_parent_id"] = parent.into();
    folder["permission"] = folder["permissions"][0].clone();
    folder
}

/// Ada owns `FOLDER_ID`, its child folder and the resource in it; a sub-folder she only reads.
fn fake_serving_a_folder_tree() -> FakePassbolt {
    let fake = fake_serving_shareable_resource(r#"{"password":"p"}"#, ada_owner_permissions());
    fake.on(
        "GET",
        &format!("/folders/{FOLDER_ID}.json"),
        folder_in(FOLDER_ID, None, 15),
    );
    fake.on(
        "GET",
        "/folders.json",
        json!([
            folder_in(FOLDER_ID, None, 15),
            folder_in(CHILD_FOLDER_ID, Some(FOLDER_ID), 15),
            folder_in(FOREIGN_FOLDER_ID, Some(FOLDER_ID), 1)
        ]),
    );
    let mut resource = data::listed_resource(RESOURCE_ID);
    resource["folder_parent_id"] = CHILD_FOLDER_ID.into();
    resource["permission"] = data::permission("p-ada", "User", ADA_ID, 15);
    fake.on("GET", "/resources.json", json!([resource]));
    fake.on(
        "GET",
        &format!("/folders/{CHILD_FOLDER_ID}.json"),
        folder_in(CHILD_FOLDER_ID, Some(FOLDER_ID), 15),
    );
    for id in [FOLDER_ID, CHILD_FOLDER_ID, FOREIGN_FOLDER_ID] {
        fake.on("PUT", &folder_share_path(id), Value::Null);
    }
    fake
}

/// `folder_in`, betty reading it with the permission `permission_id`.
fn folder_betty_reads(id: &str, parent: Option<&str>, permission_id: &str) -> Value {
    let mut folder = folder_in(id, parent, 15);
    folder["permissions"]
        .as_array_mut()
        .unwrap()
        .push(data::permission(permission_id, "User", BETTY_ID, 1));
    folder
}

async fn share_folder_with_betty(fake: &FakePassbolt, with_content: bool) {
    let client = login_ada(fake).await;
    passbolt_sdk::folder::share::share_folder(
        &client,
        FOLDER_ID,
        &[BETTY_ID.into()],
        &[],
        7,
        with_content,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn sharing_a_folder_updates_an_existing_permission() {
    let fake = FakePassbolt::new();
    let mut folder = data::folder(json!([data::permission("p-betty", "User", BETTY_ID, 1)]));
    folder["permission"] = data::permission("p-ada", "User", ADA_ID, 15);
    fake.on("GET", &format!("/folders/{FOLDER_ID}.json"), folder);
    fake.on("PUT", &folder_share_path(FOLDER_ID), Value::Null);

    share_folder_with_betty(&fake, false).await;

    assert_eq!(
        fake.body_of("PUT", &folder_share_path(FOLDER_ID))["permissions"],
        json!([{ "id": "p-betty", "aro": "User", "aro_foreign_key": BETTY_ID, "type": 7 }])
    );
}

#[tokio::test]
async fn sharing_a_folder_alone_leaves_its_content() {
    let fake = fake_serving_a_folder_tree();

    share_folder_with_betty(&fake, false).await;

    assert!(fake
        .requests_to("PUT", &folder_share_path(CHILD_FOLDER_ID))
        .is_empty());
    assert!(fake.requests_to("PUT", &share_path()).is_empty());
}

#[tokio::test]
async fn sharing_a_folder_with_its_content_shares_what_the_user_owns() {
    let fake = fake_serving_a_folder_tree();

    share_folder_with_betty(&fake, true).await;

    assert_eq!(
        fake.requests_to("PUT", &folder_share_path(CHILD_FOLDER_ID))
            .len(),
        1
    );
    assert!(
        fake.requests_to("PUT", &folder_share_path(FOREIGN_FOLDER_ID))
            .is_empty(),
        "ada does not own it"
    );
    let resource_share = fake.body_of("PUT", &share_path());
    assert_eq!(secret_user_ids(&resource_share), BTreeSet::from([BETTY_ID]));
    let listed = &fake.requests_to("GET", "/resources.json")[0];
    assert_eq!(
        listed.query_values("filter[has-parent][]").len(),
        2,
        "the folder and its owned child"
    );
}

#[tokio::test]
async fn sharing_with_the_permission_already_given_sends_nothing() {
    let fake = fake_serving_shareable_resource(
        r#"{"password":"p"}"#,
        ada_owner_betty_reader_permissions(),
    );
    let client = login_ada(&fake).await;

    share_with(&client, &[BETTY_ID], &[], 1).await.unwrap();

    assert!(fake.requests_to("PUT", &share_path()).is_empty());
    assert!(fake
        .requests_to(
            "POST",
            &format!("/share/simulate/resource/{RESOURCE_ID}.json")
        )
        .is_empty());
}

#[tokio::test]
async fn sharing_shared_v5_metadata_leaves_the_resource_untouched() {
    let fake = FakePassbolt::new();
    fake.with_directory();
    let resource = data::resource_v5_with_secret(
        "v5-default",
        &data::metadata("GitHub"),
        (&METADATA, "shared_key", "mk1"),
        r#"{"object_type":"PASSBOLT_SECRET_DATA","password":"p"}"#,
    );
    fake.on("GET", &resource_path(), resource);
    fake.on(
        "GET",
        &format!("/permissions/resource/{RESOURCE_ID}.json"),
        ada_owner_permissions(),
    );
    fake.on("PUT", &share_path(), Value::Null);
    let client = login_ada(&fake).await;

    share_with(&client, &[BETTY_ID], &[], 1).await.unwrap();

    assert!(fake.requests_to("PUT", &resource_path()).is_empty());
    assert_eq!(fake.requests_to("PUT", &share_path()).len(), 1);
}

#[tokio::test]
async fn revoking_a_group_deletes_its_permission() {
    let permissions = json!([
        data::permission("p-ada", "User", ADA_ID, 15),
        data::permission("p-ops", "Group", GROUP_ID, 1)
    ]);
    let fake = fake_serving_shareable_resource(r#"{"password":"p"}"#, permissions);
    let client = login_ada(&fake).await;

    share_with(&client, &[], &[GROUP_ID], -1).await.unwrap();

    assert_eq!(
        fake.body_of("PUT", &share_path())["permissions"],
        json!([{ "id": "p-ops", "aro": "Group", "aro_foreign_key": GROUP_ID, "delete": true }])
    );
}

#[tokio::test]
async fn removing_a_user_who_is_not_a_member_is_refused() {
    let fake = fake_serving_group();
    let client = login_ada(&fake).await;

    let error = group_update::update_group(&client, GROUP_ID, None, &[], &[], &[CAROL_ID.into()])
        .await
        .unwrap_err();

    assert!(
        matches!(error, PassboltError::InvalidArgument(_)),
        "{error:?}"
    );
    assert!(fake.requests_to("PUT", &group_path()).is_empty());
}

#[tokio::test]
async fn adding_a_member_with_the_role_they_have_changes_nothing() {
    let fake = fake_serving_group();
    let client = login_ada(&fake).await;

    group_update::update_group(&client, GROUP_ID, None, &[BETTY_ID.into()], &[], &[])
        .await
        .unwrap();

    assert!(fake.requests_to("PUT", &group_path()).is_empty());
}

#[rstest::rstest]
#[case::revoked(include_str!("../fixtures/keys/revoked_public.asc"), "revoked")]
#[case::expired(include_str!("../fixtures/keys/expired_public.asc"), "expired")]
#[tokio::test]
async fn sharing_with_a_user_whose_key_is_unusable_sends_nothing(
    #[case] betty_key: &str,
    #[case] reason: &str,
) {
    let fake = fake_serving_shareable_resource(
        r#"{"password":"p","description":"d"}"#,
        ada_owner_permissions(),
    );
    let mut betty = data::user("betty");
    betty["gpgkey"]["armored_key"] = betty_key.into();
    fake.on("GET", &format!("/users/{BETTY_ID}.json"), betty);
    let client = login_ada(&fake).await;

    let error = share_with(&client, &[BETTY_ID], &[], 7).await.unwrap_err();

    assert!(error.to_string().contains(reason), "{error}");
    assert!(fake.requests_to("PUT", &share_path()).is_empty());
}

#[tokio::test]
async fn raising_an_access_on_a_folder_only_reaches_the_content_the_user_has() {
    let fake = fake_serving_a_folder_tree();
    fake.on(
        "GET",
        &format!("/folders/{FOLDER_ID}.json"),
        folder_betty_reads(FOLDER_ID, None, "p-betty-root"),
    );
    fake.on(
        "GET",
        &format!("/folders/{CHILD_FOLDER_ID}.json"),
        folder_betty_reads(CHILD_FOLDER_ID, Some(FOLDER_ID), "p-betty-child"),
    );

    share_folder_with_betty(&fake, true).await;

    assert_eq!(
        fake.body_of("PUT", &folder_share_path(CHILD_FOLDER_ID))["permissions"],
        json!([{ "id": "p-betty-child", "aro": "User", "aro_foreign_key": BETTY_ID, "type": 7 }]),
        "the child's own permission"
    );
    assert!(
        fake.requests_to("PUT", &share_path()).is_empty(),
        "betty has no access to the resource"
    );
}

#[tokio::test]
async fn a_folder_already_shared_so_copies_nothing_to_its_content() {
    let fake = fake_serving_a_folder_tree();
    let mut folder = folder_betty_reads(FOLDER_ID, None, "p-betty-root");
    folder["permissions"][1]["type"] = 7.into();
    fake.on("GET", &format!("/folders/{FOLDER_ID}.json"), folder);

    share_folder_with_betty(&fake, true).await;

    for id in [FOLDER_ID, CHILD_FOLDER_ID] {
        assert!(fake.requests_to("PUT", &folder_share_path(id)).is_empty());
    }
    assert!(fake.requests_to("PUT", &share_path()).is_empty());
}

#[tokio::test]
async fn revoking_someone_without_access_changes_nothing_for_the_others() {
    let fake = fake_serving_shareable_resource(
        r#"{"password":"p"}"#,
        ada_owner_betty_reader_permissions(),
    );
    let client = login_ada(&fake).await;

    let error = share_with(&client, &[BETTY_ID, CAROL_ID], &[], -1)
        .await
        .unwrap_err();

    assert!(error.to_string().contains(CAROL_ID), "{error}");
    assert!(!error.to_string().contains(BETTY_ID), "{error}");
    assert!(fake.requests_to("PUT", &share_path()).is_empty());
}

#[tokio::test]
async fn adding_a_manager_as_member_keeps_them_manager() {
    let fake = fake_serving_group();
    let client = login_ada(&fake).await;

    // Ada manages the group already.
    group_update::update_group(
        &client,
        GROUP_ID,
        Some("Ops renamed"),
        &[ADA_ID.into()],
        &[],
        &[],
    )
    .await
    .unwrap();

    let body = fake.body_of("PUT", &group_path());
    let membership_changes = body.get("groups_users").and_then(Value::as_array);
    assert!(membership_changes.is_none_or(Vec::is_empty), "{body}");
}
