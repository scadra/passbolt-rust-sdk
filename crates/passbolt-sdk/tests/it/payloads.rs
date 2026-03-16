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

use passbolt_sdk::group::update::update_group;
use passbolt_sdk::user::update::update_user;
use serde_json::{json, Value};

use crate::common::*;

fn group_path() -> String {
    format!("/groups/{GROUP_ID}.json")
}

fn betty_path() -> String {
    format!("/users/{BETTY_ID}.json")
}

async fn logged_in_accepting_group_update() -> (FakePassbolt, Client) {
    let fake = FakePassbolt::new();
    fake.on("GET", &group_path(), data::group());
    fake.on(
        "PUT",
        &format!("/groups/{GROUP_ID}/dry-run.json"),
        json!({"dry-run": {"SecretsNeeded": [], "Secrets": []}}),
    );
    fake.on("PUT", &group_path(), data::group());
    let client = login_ada(&fake).await;
    (fake, client)
}

async fn updated_betty_body(first_name: Option<&str>, last_name: Option<&str>) -> Value {
    let fake = FakePassbolt::new();
    fake.on("PUT", &betty_path(), data::user("betty"));
    let client = login_ada(&fake).await;

    update_user(&client, BETTY_ID, first_name, last_name, None)
        .await
        .unwrap();

    fake.body_of("PUT", &betty_path())
}

#[tokio::test]
async fn renaming_a_group_sends_no_membership() {
    let (fake, client) = logged_in_accepting_group_update().await;

    update_group(&client, GROUP_ID, Some("Platform"), &[], &[], false)
        .await
        .unwrap();

    assert_eq!(
        fake.body_of("PUT", &group_path()),
        json!({ "name": "Platform" })
    );
}

#[tokio::test]
async fn an_empty_group_name_keeps_the_current_one() {
    let (fake, client) = logged_in_accepting_group_update().await;

    update_group(&client, GROUP_ID, Some(""), &[CAROL_ID.into()], &[], false)
        .await
        .unwrap();

    assert!(fake.body_of("PUT", &group_path()).get("name").is_none());
}

#[tokio::test]
async fn added_managers_come_first_and_are_not_repeated_as_members() {
    let (fake, client) = logged_in_accepting_group_update().await;

    update_group(
        &client,
        GROUP_ID,
        None,
        &[CAROL_ID.into(), ERIN_ID.into()],
        &[ERIN_ID.into()],
        false,
    )
    .await
    .unwrap();

    assert_eq!(
        fake.body_of("PUT", &group_path())["groups_users"],
        json!([
            { "user_id": ERIN_ID, "is_admin": true },
            { "user_id": CAROL_ID, "is_admin": false }
        ])
    );
}

#[tokio::test]
async fn updating_a_user_without_names_sends_no_profile() {
    let body = updated_betty_body(None, None).await;

    assert_eq!(body, json!({}));
}

#[tokio::test]
async fn updating_a_first_name_sends_only_that_name() {
    let body = updated_betty_body(Some("Bea"), None).await;

    assert_eq!(body, json!({ "profile": { "first_name": "Bea" } }));
}

#[tokio::test]
async fn updating_a_last_name_sends_only_that_name() {
    let body = updated_betty_body(None, Some("Smith")).await;

    assert_eq!(body, json!({ "profile": { "last_name": "Smith" } }));
}
