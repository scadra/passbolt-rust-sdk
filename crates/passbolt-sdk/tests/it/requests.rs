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

use passbolt_sdk::types::PasswordExpirySettings;
use passbolt_sdk::{ApiError, FolderQuery, GroupQuery, PassboltError, ResourceQuery, UserQuery};
use serde_json::{json, Value};

use crate::common::fake::RecordedRequest;
use crate::common::*;

const FAVORITE_ID: &str = "4f5a6b7c-0000-4000-8000-0000000000fa";
const COMMENT_ID: &str = "2d3e4f5a-0000-4000-8000-0000000000d1";
const TAG_ID: &str = "3e4f5a6b-0000-4000-8000-0000000000c1";
const SETTINGS_ID: &str = "6a7b8c9d-0000-4000-8000-0000000000e5";

async fn logged_in_with(method: &'static str, path: &str, body: Value) -> (FakePassbolt, Client) {
    let fake = FakePassbolt::new();
    fake.on(method, path, body);
    let client = login_ada(&fake).await;
    (fake, client)
}

fn single_request(fake: &FakePassbolt, method: &str, path: &str) -> RecordedRequest {
    let requests = fake.requests_to(method, path);
    assert_eq!(requests.len(), 1, "{method} {path} calls");
    requests[0].clone()
}

const OTHER_RESOURCE_ID: &str = "7a5b2c30-0000-4000-8000-0000000000e2";

#[tokio::test]
async fn delete_resources_deletes_them_one_by_one_as_the_api_has_no_bulk_delete() {
    let (fake, client) = logged_in_with("DELETE", &resource_path(), Value::Null).await;
    fake.on(
        "DELETE",
        &format!("/resources/{OTHER_RESOURCE_ID}.json"),
        Value::Null,
    );

    client
        .delete_resources(&[RESOURCE_ID.into(), OTHER_RESOURCE_ID.into()])
        .await
        .unwrap();

    let request = single_request(&fake, "DELETE", &resource_path());
    assert_eq!(request.header("X-CSRF-Token"), Some(CSRF_TOKEN));
    single_request(
        &fake,
        "DELETE",
        &format!("/resources/{OTHER_RESOURCE_ID}.json"),
    );
    assert!(fake.requests_to("DELETE", "/resources.json").is_empty());
}

#[tokio::test]
async fn delete_resources_stops_at_the_first_failure() {
    let fake = FakePassbolt::new();
    fake.on_error_saying(
        "DELETE",
        &resource_path(),
        404,
        "The resource does not exist.",
    );
    let client = login_ada(&fake).await;

    let error = client
        .delete_resources(&[RESOURCE_ID.into(), OTHER_RESOURCE_ID.into()])
        .await
        .unwrap_err();

    assert!(
        matches!(error, PassboltError::Api(ApiError { status: 404, .. })),
        "{error:?}"
    );
    assert!(fake
        .requests_to("DELETE", &format!("/resources/{OTHER_RESOURCE_ID}.json"))
        .is_empty());
}

#[tokio::test]
async fn a_user_that_can_be_deleted_has_no_blocker() {
    let path = format!("/users/{BETTY_ID}/dry-run.json");
    let (fake, client) = logged_in_with("DELETE", &path, Value::Null).await;

    let dry_run = client.delete_user_dry_run(BETTY_ID).await.unwrap();

    single_request(&fake, "DELETE", &path);
    assert_eq!(
        dry_run.resources_sole_owner_count + dry_run.groups_sole_manager_count,
        0
    );
}

#[tokio::test]
async fn a_user_dry_run_counts_what_blocks_the_deletion() {
    let path = format!("/users/{BETTY_ID}/dry-run.json");
    let fake = FakePassbolt::new();
    fake.on_error_with_body(
        "DELETE",
        &path,
        400,
        "The user cannot be deleted.",
        data::user_delete_blockers(),
    );
    let client = login_ada(&fake).await;

    let dry_run = client.delete_user_dry_run(BETTY_ID).await.unwrap();

    assert_eq!(
        (
            dry_run.resources_sole_owner_count,
            dry_run.folders_sole_owner_count,
            dry_run.groups_sole_manager_count
        ),
        (2, 0, 1)
    );
}

#[tokio::test]
async fn a_group_dry_run_is_a_delete() {
    let path = format!("/groups/{GROUP_ID}/dry-run.json");
    let (fake, client) = logged_in_with("DELETE", &path, json!([])).await;

    let dry_run = client.delete_group_dry_run(GROUP_ID).await.unwrap();

    single_request(&fake, "DELETE", &path);
    assert_eq!(dry_run.resources_sole_group_count, 0);
}

#[tokio::test]
async fn move_resource_sends_the_new_parent() {
    let path = format!("/move/resource/{RESOURCE_ID}.json");
    let (fake, client) = logged_in_with("PUT", &path, Value::Null).await;

    client
        .move_resource(RESOURCE_ID, Some(FOLDER_ID))
        .await
        .unwrap();

    assert_eq!(
        fake.body_of("PUT", &path),
        json!({ "folder_parent_id": FOLDER_ID })
    );
}

#[tokio::test]
async fn move_folder_to_the_root_sends_a_null_parent() {
    let path = format!("/move/folder/{FOLDER_ID}.json");
    let (fake, client) = logged_in_with("PUT", &path, Value::Null).await;

    client.move_folder(FOLDER_ID, None).await.unwrap();

    assert_eq!(
        fake.body_of("PUT", &path),
        json!({ "folder_parent_id": null })
    );
}

#[tokio::test]
async fn update_resource_tags_replaces_them_like_the_browser_extension() {
    let path = format!("/tags/{RESOURCE_ID}.json");
    let (fake, client) =
        logged_in_with("POST", &path, json!([data::tag("prod"), data::tag("ops")])).await;

    let tags = client
        .update_resource_tags(RESOURCE_ID, &["prod".into(), "ops".into()])
        .await
        .unwrap();

    assert_eq!(
        fake.body_of("POST", &path),
        json!({ "tags": ["prod", "ops"] })
    );
    assert_eq!(tags.len(), 2);
}

#[tokio::test]
async fn add_tag_to_resource_keeps_the_other_tags() {
    let path = format!("/tags/{RESOURCE_ID}.json");
    let (fake, client) =
        logged_in_with("POST", &path, json!([data::tag("ops"), data::tag("prod")])).await;
    let mut resource = data::resource_v4("password-string", "p");
    resource["tags"] = json!([data::tag("ops")]);
    fake.on("GET", &resource_path(), resource);

    let tags = client
        .add_tag_to_resource(RESOURCE_ID, "prod")
        .await
        .unwrap();

    assert_eq!(
        fake.body_of("POST", &path),
        json!({ "tags": ["ops", "prod"] })
    );
    assert_eq!(tags.len(), 2);
    let read = &fake.requests_to("GET", &resource_path())[0];
    assert_eq!(read.query_value("contain[tag]").as_deref(), Some("1"));
}

#[tokio::test]
async fn update_tag_puts_the_new_slug() {
    let path = format!("/tags/{TAG_ID}.json");
    let (fake, client) = logged_in_with("PUT", &path, data::tag("staging")).await;

    client.update_tag(TAG_ID, "staging").await.unwrap();

    assert_eq!(fake.body_of("PUT", &path), json!({ "slug": "staging" }));
}

#[tokio::test]
async fn delete_tag_targets_the_tag() {
    let path = format!("/tags/{TAG_ID}.json");
    let (fake, client) = logged_in_with("DELETE", &path, Value::Null).await;

    client.delete_tag(TAG_ID).await.unwrap();

    assert_eq!(fake.requests_to("DELETE", &path).len(), 1);
}

#[tokio::test]
async fn get_tags_reads_the_tag_list() {
    let (_fake, client) = logged_in_with("GET", "/tags.json", json!([data::tag("prod")])).await;

    let tags = client.get_tags().await.unwrap();

    assert_eq!(tags[0].slug, "prod");
}

#[tokio::test]
async fn create_comment_sends_the_parent_when_given() {
    let path = format!("/comments/resource/{RESOURCE_ID}.json");
    let (fake, client) = logged_in_with("POST", &path, data::comment()).await;

    client
        .create_comment(RESOURCE_ID, "Agreed", Some(COMMENT_ID))
        .await
        .unwrap();

    assert_eq!(
        fake.body_of("POST", &path),
        json!({ "content": "Agreed", "parent_id": COMMENT_ID })
    );
}

#[tokio::test]
async fn create_comment_without_parent_sends_only_the_content() {
    let path = format!("/comments/resource/{RESOURCE_ID}.json");
    let (fake, client) = logged_in_with("POST", &path, data::comment()).await;

    let comment = client
        .create_comment(RESOURCE_ID, "Rotated last week", None)
        .await
        .unwrap();

    assert_eq!(
        fake.body_of("POST", &path),
        json!({ "content": "Rotated last week" })
    );
    assert_eq!(comment.id, COMMENT_ID);
}

#[tokio::test]
async fn get_comments_asks_for_the_creator() {
    let path = format!("/comments/resource/{RESOURCE_ID}.json");
    let (fake, client) = logged_in_with("GET", &path, json!([data::comment()])).await;

    let comments = client.get_comments(RESOURCE_ID).await.unwrap();

    assert_eq!(comments.len(), 1);
    assert_eq!(
        single_request(&fake, "GET", &path)
            .query_value("contain[creator]")
            .as_deref(),
        Some("1")
    );
}

#[tokio::test]
async fn delete_comment_targets_the_comment() {
    let path = format!("/comments/{COMMENT_ID}.json");
    let (fake, client) = logged_in_with("DELETE", &path, Value::Null).await;

    client.delete_comment(COMMENT_ID).await.unwrap();

    assert_eq!(fake.requests_to("DELETE", &path).len(), 1);
}

#[tokio::test]
async fn add_favorite_posts_an_empty_object() {
    let path = format!("/favorites/resource/{RESOURCE_ID}.json");
    let (fake, client) = logged_in_with("POST", &path, data::favorite()).await;

    let favorite = client.add_favorite(RESOURCE_ID).await.unwrap();

    let request = single_request(&fake, "POST", &path);
    assert_eq!(request.json_body(), &json!({}));
    assert_eq!(request.header("X-CSRF-Token"), Some(CSRF_TOKEN));
    assert_eq!(favorite.id.as_deref(), Some(FAVORITE_ID));
}

#[tokio::test]
async fn remove_favorite_targets_the_favorite_not_the_resource() {
    let path = format!("/favorites/{FAVORITE_ID}.json");
    let (fake, client) = logged_in_with("DELETE", &path, Value::Null).await;

    client.remove_favorite(FAVORITE_ID).await.unwrap();

    assert_eq!(
        single_request(&fake, "DELETE", &path).header("X-CSRF-Token"),
        Some(CSRF_TOKEN)
    );
}

#[tokio::test]
async fn save_password_expiry_settings_posts_the_settings() {
    let path = "/password-expiry/settings.json";
    let (fake, client) = logged_in_with("POST", path, data::password_expiry_settings()).await;
    let settings = PasswordExpirySettings {
        id: None,
        default_expiry_period_days: None,
        policy_override: Some(false),
        automatic_expiry: Some(true),
        automatic_update: Some(true),
    };

    let saved = client
        .save_password_expiry_settings(&settings)
        .await
        .unwrap();

    let body = fake.body_of("POST", path);
    assert_eq!(body["automatic_expiry"], true);
    assert_eq!(body["automatic_update"], true);
    assert_eq!(body["policy_override"], false);
    assert_eq!(saved.id.as_deref(), Some(SETTINGS_ID));
}

#[tokio::test]
async fn password_expiry_settings_use_the_api_field_for_the_default_period() {
    let (_fake, client) = logged_in_with(
        "GET",
        "/password-expiry/settings.json",
        data::password_expiry_settings(),
    )
    .await;

    let settings = client.get_password_expiry_settings().await.unwrap();

    assert_eq!(settings.default_expiry_period_days, Some(90));
}

#[tokio::test]
async fn delete_password_expiry_settings_targets_the_settings() {
    let path = format!("/password-expiry/settings/{SETTINGS_ID}.json");
    let (fake, client) = logged_in_with("DELETE", &path, Value::Null).await;

    client
        .delete_password_expiry_settings(SETTINGS_ID)
        .await
        .unwrap();

    assert_eq!(fake.requests_to("DELETE", &path).len(), 1);
}

#[tokio::test]
async fn search_aros_encodes_the_search_term() {
    let path = "/share/search-aros.json";
    let (fake, client) = logged_in_with("GET", path, data::aros()).await;

    let aros = client.search_aros("betty & co/ops").await.unwrap();

    let request = single_request(&fake, "GET", path);
    assert_eq!(request.query, "filter%5Bsearch%5D=betty%20%26%20co%2Fops");
    assert_eq!(
        request.query_value("filter[search]").as_deref(),
        Some("betty & co/ops")
    );
    assert_eq!(aros.len(), 2);
}

#[tokio::test]
async fn get_users_sends_every_filter() {
    let (fake, client) = logged_in_with("GET", "/users.json", json!([])).await;

    client
        .get_users(UserQuery {
            search: Some("ada".into()),
            group_id: Some(GROUP_ID.into()),
            resource_id: Some(RESOURCE_ID.into()),
            admin_only: true,
            ..Default::default()
        })
        .await
        .unwrap();

    let request = single_request(&fake, "GET", "/users.json");
    assert_eq!(
        request.query_value("filter[search]").as_deref(),
        Some("ada")
    );
    assert_eq!(
        request.query_value("filter[has-groups]").as_deref(),
        Some(GROUP_ID)
    );
    assert_eq!(
        request.query_value("filter[has-access]").as_deref(),
        Some(RESOURCE_ID)
    );
    assert_eq!(
        request.query_value("filter[is-admin]").as_deref(),
        Some("1")
    );
}

#[tokio::test]
async fn get_users_without_filters_only_asks_for_the_contained_data() {
    let (fake, client) = logged_in_with("GET", "/users.json", json!([])).await;

    client.get_users(UserQuery::default()).await.unwrap();

    let request = single_request(&fake, "GET", "/users.json");
    assert!(!request.query.contains("filter"), "{}", request.query);
    for contained in ["contain[role]", "contain[gpgkey]", "contain[groups_users]"] {
        assert_eq!(
            request.query_value(contained).as_deref(),
            Some("1"),
            "{contained}"
        );
    }
}

#[tokio::test]
async fn get_folders_sends_the_filters_the_api_has() {
    let mut other_folder = data::folder(json!([]));
    other_folder["id"] = "5f6e7d8c-0000-4000-8000-0000000000f2".into();
    let shared_with_the_group =
        data::folder(json!([data::permission("p-ops", "Group", GROUP_ID, 1)]));
    let (fake, client) = logged_in_with(
        "GET",
        "/folders.json",
        json!([shared_with_the_group, other_folder]),
    )
    .await;

    let folders = client
        .get_folders(FolderQuery {
            search: Some("ops".into()),
            group_id: Some(GROUP_ID.into()),
            parent_folder_ids: vec![FOLDER_ID.into(), "parent-2".into()],
            ..Default::default()
        })
        .await
        .unwrap();

    let request = single_request(&fake, "GET", "/folders.json");
    assert_eq!(
        request.query_value("filter[search]").as_deref(),
        Some("ops")
    );
    assert_eq!(
        request.query_values("filter[has-parent][]"),
        [FOLDER_ID, "parent-2"]
    );
    assert_eq!(
        request.query_value("filter[is-shared-with-group]"),
        None,
        "not an API filter"
    );
    let ids: Vec<&str> = folders.iter().map(|folder| folder.id.as_str()).collect();
    assert_eq!(
        ids,
        [FOLDER_ID],
        "the group filter applies to the permissions"
    );
}

#[tokio::test]
async fn get_folders_without_filters_sends_none() {
    let (fake, client) = logged_in_with("GET", "/folders.json", json!([])).await;

    client.get_folders(FolderQuery::default()).await.unwrap();

    let request = single_request(&fake, "GET", "/folders.json");
    assert!(!request.query.contains("filter"), "{}", request.query);
}

#[tokio::test]
async fn get_groups_sends_every_filter() {
    let (fake, client) = logged_in_with("GET", "/groups.json", json!([data::group()])).await;

    let groups = client
        .get_groups(GroupQuery {
            user_id: Some(BETTY_ID.into()),
            manager_id: Some(ADA_ID.into()),
            ..Default::default()
        })
        .await
        .unwrap();

    let request = single_request(&fake, "GET", "/groups.json");
    assert_eq!(
        request.query_value("filter[has-users]").as_deref(),
        Some(BETTY_ID)
    );
    assert_eq!(
        request.query_value("filter[has-managers]").as_deref(),
        Some(ADA_ID)
    );
    assert_eq!(groups[0].id, GROUP_ID);
}

#[tokio::test]
async fn get_groups_without_filters_sends_none() {
    let (fake, client) = logged_in_with("GET", "/groups.json", json!([])).await;

    client.get_groups(GroupQuery::default()).await.unwrap();

    let request = single_request(&fake, "GET", "/groups.json");
    assert!(!request.query.contains("filter"), "{}", request.query);
}

#[tokio::test]
async fn get_resources_sends_every_filter() {
    let (fake, client) = logged_in_with("GET", "/resources.json", json!([])).await;

    client
        .get_resources(ResourceQuery {
            favorites_only: true,
            owned_by_me: true,
            group_ids: vec![GROUP_ID.into()],
            folder_ids: vec![FOLDER_ID.into()],
            search: Some("git".into()),
            ..Default::default()
        })
        .await
        .unwrap();

    let request = single_request(&fake, "GET", "/resources.json");
    assert_eq!(
        request
            .query_value("filter[is-shared-with-group]")
            .as_deref(),
        Some(GROUP_ID)
    );
    assert_eq!(request.query_values("filter[has-parent][]"), [FOLDER_ID]);
    assert_eq!(
        request.query_value("filter[is-favorite]").as_deref(),
        Some("1")
    );
    assert_eq!(
        request.query_value("filter[is-owned-by-me]").as_deref(),
        Some("1")
    );
    assert_eq!(
        request.query_value("filter[search]").as_deref(),
        Some("git")
    );
}

#[tokio::test]
async fn get_resources_filters_on_one_group_only() {
    let (fake, client) = logged_in_with("GET", "/resources.json", json!([])).await;

    let error = client
        .get_resources(ResourceQuery {
            group_ids: vec![GROUP_ID.into(), GROUP_ID.into()],
            ..Default::default()
        })
        .await
        .unwrap_err();

    assert!(
        matches!(error, PassboltError::InvalidArgument(_)),
        "{error:?}"
    );
    assert!(fake.requests_to("GET", "/resources.json").is_empty());
}

async fn client_blocked_from_deleting_betty() -> (FakePassbolt, Client) {
    let fake = FakePassbolt::new();
    fake.on_error_with_body(
        "DELETE",
        &format!("/users/{BETTY_ID}/dry-run.json"),
        400,
        "The user cannot be deleted.",
        data::user_delete_blockers(),
    );
    fake.on("DELETE", &format!("/users/{BETTY_ID}.json"), Value::Null);
    let client = login_ada(&fake).await;
    (fake, client)
}

#[tokio::test]
async fn the_user_delete_blockers_list_the_items_groups_and_groups_deleted_too() {
    let (_fake, client) = client_blocked_from_deleting_betty().await;

    let blockers = client.user_delete_blockers(BETTY_ID).await.unwrap();

    assert_eq!(blockers.resources.len(), 2);
    assert_eq!(blockers.resources[0].permissions.len(), 2);
    assert_eq!(blockers.groups[0].name, "Ops");
    assert_eq!(
        blockers.groups_to_delete,
        ["9c7d4b20-0000-4000-8000-000000000961"]
    );
}

#[tokio::test]
async fn deleting_with_a_transfer_sends_the_successor_permissions_and_membership() {
    let (fake, client) = client_blocked_from_deleting_betty().await;
    let blockers = client.user_delete_blockers(BETTY_ID).await.unwrap();

    let transfer = blockers.transfer_to(CAROL_ID).unwrap();
    client
        .delete_user_with_transfer(BETTY_ID, &transfer)
        .await
        .unwrap();

    assert_eq!(
        fake.body_of("DELETE", &format!("/users/{BETTY_ID}.json")),
        json!({"transfer": {
            "owners": [
                {"id": "3e4f5a60-0000-4000-8000-0000000000a2", "aco_foreign_key": "7a5b2c30-0000-4000-8000-0000000000e1"},
                {"id": "3e4f5a60-0000-4000-8000-0000000000b2", "aco_foreign_key": "7a5b2c30-0000-4000-8000-0000000000e2"}
            ],
            "managers": [
                {"id": "6d8e9f10-0000-4000-8000-0000000000c2", "group_id": GROUP_ID}
            ]
        }})
    );
}

#[tokio::test]
async fn a_successor_without_access_to_everything_is_refused() {
    let (_fake, client) = client_blocked_from_deleting_betty().await;
    let blockers = client.user_delete_blockers(BETTY_ID).await.unwrap();

    let error = blockers.transfer_to(ERIN_ID).unwrap_err();

    assert!(error.to_string().contains("has no access"), "{error}");
}

#[tokio::test]
async fn nothing_blocks_a_dry_run_that_succeeds() {
    let path = format!("/groups/{GROUP_ID}/dry-run.json");
    let (_fake, client) = logged_in_with("DELETE", &path, json!([])).await;

    assert!(client
        .group_delete_blockers(GROUP_ID)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn deleting_a_folder_with_its_content_asks_the_cascade() {
    let path = format!("/folders/{FOLDER_ID}.json");
    let (fake, client) = logged_in_with("DELETE", &path, Value::Null).await;

    client.delete_folder_with_content(FOLDER_ID).await.unwrap();

    let request = single_request(&fake, "DELETE", &path);
    assert_eq!(request.query_value("cascade").as_deref(), Some("1"));
}

#[tokio::test]
async fn keeping_the_session_alive_reads_the_user() {
    let (fake, client) = logged_in_with("GET", "/users/me.json", data::user("ada")).await;
    let before = fake.requests_to("GET", "/users/me.json").len();

    client.keep_alive().await.unwrap();

    assert_eq!(fake.requests_to("GET", "/users/me.json").len(), before + 1);
}
