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

use passbolt_sdk::filter::Filter;
use passbolt_sdk::resource::get::get_resource_view;
use passbolt_sdk::resource::list::list_resources;
use passbolt_sdk::resource::view::ResourceView;
use passbolt_sdk::ResourceQuery;
use serde_json::json;

use crate::common::*;

async fn list(
    fake: &FakePassbolt,
    query: ResourceQuery,
    filters: &[Filter],
    secret_workers: Option<usize>,
) -> Vec<ResourceView> {
    fake.with_directory();
    let client = login_ada(fake).await;
    list_resources(&client, query, filters, secret_workers)
        .await
        .unwrap()
}

fn names(views: &[ResourceView]) -> Vec<&str> {
    views.iter().map(|view| view.name.as_str()).collect()
}

/// A v4 GitHub and a v5 GitLab with personal metadata.
fn fake_serving_v4_and_v5() -> FakePassbolt {
    let fake = FakePassbolt::new();
    let mut github = data::resource_v4(
        "password-and-description",
        r#"{"password":"v4-password","description":"v4 notes"}"#,
    );
    github["name"] = "GitHub".into();
    github["username"] = "ada".into();
    let mut gitlab_metadata = data::metadata("GitLab");
    gitlab_metadata["username"] = "lovelace".into();
    let mut gitlab = data::resource_v5_with_secret(
        "v5-default",
        &gitlab_metadata,
        (&ADA, "user_key", "8b6c3a10-0000-4000-8000-000000008888"),
        r#"{"object_type":"PASSBOLT_SECRET_DATA","password":"v5-password"}"#,
    );
    gitlab["id"] = "7a5b2c30-0000-4000-8000-0000000000e2".into();
    fake.on("GET", "/resources.json", json!([github, gitlab]));
    fake
}

#[tokio::test]
async fn search_matches_decrypted_v5_names_the_server_cannot_search() {
    let fake = fake_serving_v4_and_v5();

    let views = list(
        &fake,
        ResourceQuery {
            search: Some("lab".into()),
            ..ResourceQuery::default()
        },
        &[],
        None,
    )
    .await;

    assert_eq!(names(&views), ["GitLab"]);
}

#[tokio::test]
async fn filters_apply_to_decrypted_fields() {
    let fake = fake_serving_v4_and_v5();
    let filter = Filter::parse("username=lovelace").unwrap();

    let views = list(&fake, ResourceQuery::default(), &[filter], None).await;

    assert_eq!(names(&views), ["GitLab"]);
    assert_eq!(views[0].resource_type.as_deref(), Some("v5-default"));
}

#[tokio::test]
async fn secrets_are_decrypted_only_when_asked() {
    let fake = fake_serving_v4_and_v5();

    let without = list(&fake, ResourceQuery::default(), &[], None).await;
    let with = list(&fake, ResourceQuery::default(), &[], Some(1)).await;

    assert!(without
        .iter()
        .all(|view| view.password.is_none() && view.secret.is_none()));
    let passwords: Vec<_> = with.iter().map(|view| view.password.as_deref()).collect();
    assert_eq!(passwords, [Some("v4-password"), Some("v5-password")]);
    assert_eq!(
        with[0].description, "v4 notes",
        "the v4 description is in the secret"
    );
}

#[tokio::test]
async fn folder_permissions_come_with_the_folder() {
    let fake = FakePassbolt::new();
    let permissions = json!([data::permission("p-ada", "User", ADA_ID, 15)]);
    fake.on(
        "GET",
        &format!("/folders/{FOLDER_ID}.json"),
        data::folder(permissions),
    );
    let client = login_ada(&fake).await;

    let permissions = client.get_folder_permissions(FOLDER_ID).await.unwrap();

    assert_eq!(permissions[0].permission_type, Some(15));
    assert!(
        fake.requests_to("GET", &format!("/folders/{FOLDER_ID}.json"))[0]
            .query
            .contains("permissions")
    );
}

#[tokio::test]
async fn a_resource_view_holds_the_metadata_and_the_secret() {
    let fake = FakePassbolt::new();
    fake.with_directory();
    fake.on(
        "GET",
        &resource_path(),
        data::resource_v5_with_secret(
            "v5-default",
            &data::metadata("GitHub"),
            (&ADA, "user_key", "8b6c3a10-0000-4000-8000-000000008888"),
            &data::secret_v5_default().to_string(),
        ),
    );
    let client = login_ada(&fake).await;

    let view = get_resource_view(&client, RESOURCE_ID).await.unwrap();

    assert_eq!(
        (view.name.as_str(), view.password.as_deref()),
        ("GitHub", Some("s3cr3t"))
    );
    assert_eq!(view.note(), Some("prod"));
    assert_eq!(view.metadata["custom_fields"][0]["metadata_key"], "Account");
    assert_eq!(
        view.secret.unwrap()["custom_fields"][0]["secret_value"],
        "ada-account"
    );
}

#[tokio::test]
async fn a_resource_that_does_not_decrypt_is_listed_with_its_error() {
    let fake = fake_serving_v4_and_v5();
    let mut resources = data::listed_resources(&[RESOURCE_ID]);
    let mut foreign =
        data::resource_v5(&data::metadata("Foreign"), &BETTY, "user_key", "betty-key");
    foreign.id = "7a5b2c30-0000-4000-8000-0000000000e3".into();
    resources
        .as_array_mut()
        .unwrap()
        .push(serde_json::to_value(foreign).unwrap());
    fake.on("GET", "/resources.json", resources);

    let views = list(&fake, ResourceQuery::default(), &[], None).await;

    assert_eq!(views.len(), 2);
    assert!(views[0].error.is_none());
    assert!(
        views[1]
            .error
            .as_deref()
            .is_some_and(|error| error.contains("metadata")),
        "{:?}",
        views[1].error
    );
}

#[tokio::test]
async fn search_and_filters_combine_and_a_password_filter_reads_secrets() {
    let fake = fake_serving_v4_and_v5();
    let filter = Filter::parse("password=v5-password").unwrap();

    let views = list(
        &fake,
        ResourceQuery {
            search: Some("git".into()),
            ..ResourceQuery::default()
        },
        &[filter],
        Some(1),
    )
    .await;

    assert_eq!(names(&views), ["GitLab"]);
}

#[tokio::test]
async fn a_password_string_that_looks_like_json_is_a_password() {
    let fake = FakePassbolt::new();
    let client = login_ada(&fake).await;
    let resource = data::resource("password-string", r#"{"password":"not this"}"#);

    let secret = client.decrypt_resource_secret(&resource).await.unwrap();

    assert_eq!(
        secret.password.as_deref(),
        Some(r#"{"password":"not this"}"#)
    );
}

#[tokio::test]
async fn raw_resources_are_searched_by_name_their_v5_names_decrypted() {
    let fake = FakePassbolt::new();
    fake.with_directory();
    let mut v4 = data::resource_v4("password-and-description", "p");
    v4["id"] = "7a5b2c30-0000-4000-8000-0000000000a4".into();
    v4["name"] = "GitLab".into();
    let personal_v5 = serde_json::to_value(data::resource_v5(
        &data::metadata("GitHub"),
        &ADA,
        "user_key",
        "gpgkey-ada",
    ))
    .unwrap();
    let mut other = personal_v5.clone();
    other["id"] = "7a5b2c30-0000-4000-8000-0000000000a5".into();
    other["metadata"] = ADA.encrypt(&data::metadata("Bank").to_string()).into();
    fake.on("GET", "/resources.json", json!([v4, personal_v5, other]));
    let client = login_ada(&fake).await;

    let found = client
        .get_resources(ResourceQuery {
            search: Some("git".into()),
            ..ResourceQuery::default()
        })
        .await
        .unwrap();

    let mut ids: Vec<&str> = found.iter().map(|resource| resource.id.as_str()).collect();
    ids.sort_unstable();
    assert_eq!(ids, ["7a5b2c30-0000-4000-8000-0000000000a4", RESOURCE_ID]);
}
