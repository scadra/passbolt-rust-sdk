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

//! Importing files as the browser extension does: the requests sent for the folders, the
//! resources and the tag.

use passbolt_sdk::exchange::import::{self, ImportOptions};
use serde_json::{json, Value};

use crate::common::*;
use crate::create_v5::v5_server;

const REFERENCE: &str = "import-20240131235959";
const FOLDER_ID: &str = "5f6e7d8c-0000-4000-8000-0000000000f1";

const KEEPASS_CSV: &str = include_str!("../fixtures/exchange/csv-kdbx.csv");

/// A v5 server creating folders and tags; every folder created gets `FOLDER_ID`.
fn importing_server() -> FakePassbolt {
    let fake = v5_server(data::metadata_keys_settings());
    fake.on("POST", "/folders.json", data::folder(json!([])));
    fake.on(
        "GET",
        &format!("/folders/{FOLDER_ID}.json"),
        data::folder(json!([])),
    );
    let resource_id = fake.stored("POST", "/resources.json")["id"]
        .as_str()
        .unwrap()
        .to_string();
    fake.on(
        "POST",
        &format!("/tags/{resource_id}.json"),
        json!([data::tag(REFERENCE)]),
    );
    fake
}

async fn import_keepass_csv(fake: &FakePassbolt, options: ImportOptions) -> import::ImportReport {
    let client = login_ada(fake).await;
    let types = client.resource_types().await.unwrap();
    let parsed = import::parse_csv(KEEPASS_CSV, &types, true, REFERENCE.into()).unwrap();
    import::import(&client, parsed, options).await.unwrap()
}

fn bodies(fake: &FakePassbolt, method: &str, path: &str) -> Vec<Value> {
    fake.requests_to(method, path)
        .into_iter()
        .map(|request| request.json_body().clone())
        .collect()
}

#[tokio::test]
async fn the_folders_of_the_file_are_created_below_the_import_folder() {
    let fake = importing_server();

    let report = import_keepass_csv(
        &fake,
        ImportOptions {
            folders: true,
            tags: false,
        },
    )
    .await;

    let folders: Vec<(Value, Value)> = bodies(&fake, "POST", "/folders.json")
        .into_iter()
        .map(|body| (body["name"].clone(), body["folder_parent_id"].clone()))
        .collect();
    assert_eq!(
        folders,
        [
            (json!(REFERENCE), Value::Null),
            (json!("Folder 1"), json!(FOLDER_ID)),
            (json!("a/b"), json!(FOLDER_ID)),
        ]
    );
    assert_eq!(report.folders, 3);
    assert_eq!(report.folder_id.as_deref(), Some(FOLDER_ID));
}

#[tokio::test]
async fn every_row_becomes_a_resource_in_its_folder() {
    let fake = importing_server();

    let report = import_keepass_csv(
        &fake,
        ImportOptions {
            folders: true,
            tags: false,
        },
    )
    .await;

    assert!(report.errors.is_empty(), "{:?}", report.errors);
    let resources = bodies(&fake, "POST", "/resources.json");
    assert_eq!(resources.len(), 4);
    assert_eq!(report.resources, 4);
    assert!(resources
        .iter()
        .all(|resource| resource["folder_parent_id"] == FOLDER_ID));
    assert!(report.errors.is_empty(), "{:?}", report.errors);
}

#[tokio::test]
async fn without_folders_every_resource_goes_to_the_root() {
    let fake = importing_server();

    let report = import_keepass_csv(
        &fake,
        ImportOptions {
            folders: false,
            tags: false,
        },
    )
    .await;

    assert!(fake.requests_to("POST", "/folders.json").is_empty());
    assert!(bodies(&fake, "POST", "/resources.json")
        .iter()
        .all(|resource| resource.get("folder_parent_id").is_none_or(Value::is_null)));
    assert_eq!(report.folder_id, None);
}

#[tokio::test]
async fn the_resources_are_tagged_with_the_name_of_the_import() {
    let fake = importing_server();
    let resource_id = fake.stored("POST", "/resources.json")["id"]
        .as_str()
        .unwrap()
        .to_string();

    let report = import_keepass_csv(
        &fake,
        ImportOptions {
            folders: false,
            tags: true,
        },
    )
    .await;

    let tags = bodies(&fake, "POST", &format!("/tags/{resource_id}.json"));
    assert_eq!(tags.len(), 4);
    assert!(tags
        .iter()
        .all(|body| body == &json!({"tags": [REFERENCE]})));
    assert_eq!(report.tag.as_deref(), Some(REFERENCE));
}

#[tokio::test]
async fn a_folder_that_cannot_be_created_takes_its_resources_with_it() {
    let fake = importing_server();
    fake.on_in_turn(
        "POST",
        "/folders.json",
        vec![
            (200, data::folder(json!([]))),
            (
                400,
                json!({"header": {"message": "Could not validate folder data."}}),
            ),
            (200, data::folder(json!([]))),
        ],
    );

    let report = import_keepass_csv(
        &fake,
        ImportOptions {
            folders: true,
            tags: false,
        },
    )
    .await;

    assert_eq!(report.errors[0].title, "Cannot import folder");
    assert_eq!(report.errors[0].item, format!("{REFERENCE}/Folder 1"));
    // The two resources of "Folder 1" are not imported.
    assert_eq!(report.resources, 2);
}

#[tokio::test]
async fn a_row_with_a_totp_keeps_it_and_its_notes_become_the_note() {
    let fake = importing_server();

    import_keepass_csv(
        &fake,
        ImportOptions {
            folders: false,
            tags: false,
        },
    )
    .await;

    let with_totp = &bodies(&fake, "POST", "/resources.json")[1];
    assert_eq!(
        with_totp["resource_type_id"],
        data::resource_type_id("v5-default-with-totp")
    );
    let secret = ADA.decrypt_json(secret_of(with_totp, ADA_ID));
    assert_eq!(secret["password"], "Secret 2");
    assert_eq!(secret["description"], "Description 2");
    assert_eq!(secret["totp"]["secret_key"], "TJSNMLGTCYOEMXZG");
    assert_eq!(secret["totp"]["algorithm"], "SHA1");
}

#[test]
fn a_keepass_csv_file_reads_back_as_written() {
    let format = passbolt_sdk::exchange::formats::named("csv-kdbx").unwrap();
    let table = passbolt_sdk::exchange::csv::read(KEEPASS_CSV);
    let resources: Vec<_> = table
        .rows
        .iter()
        .map(|row| (format.parse)(format, row).unwrap().normalized())
        .collect();

    let written = passbolt_sdk::exchange::export::write_csv(format, &resources);

    // The TOTP URI is written again as the browser extension writes it.
    let without_totp = |file: &str| -> Vec<String> {
        file.split("\r\n")
            .filter(|line| !line.is_empty())
            .map(|line| line.rsplit_once(',').unwrap().0.to_string())
            .collect()
    };
    assert_eq!(without_totp(&written), without_totp(KEEPASS_CSV));
}

// Each file of the browser extension's examples, read.

#[rstest::rstest]
#[case::lastpass(include_str!("../fixtures/exchange/csv-lastpass.csv"), "Password 1", "Secret 1", "Description 1")]
#[case::one_password(include_str!("../fixtures/exchange/csv-1password.csv"), "Password 1", "Secret 1", "Description 1")]
#[case::chromium(include_str!("../fixtures/exchange/csv-chromium.csv"), "Password 1", "Secret 1", "")]
#[case::bitwarden(include_str!("../fixtures/exchange/csv-bitwarden.csv"), "Password 1", "Secret 1", "Description 1")]
#[case::mozilla(include_str!("../fixtures/exchange/csv-mozilla.csv"), "https://url1.com", "Secret 1", "")]
#[case::safari(include_str!("../fixtures/exchange/csv-safari.csv"), "Password 1", "Secret 1", "Description 1")]
#[case::dashlane(include_str!("../fixtures/exchange/csv-dashlane.csv"), "Password 1", "Secret 1", "Description 1")]
fn an_example_file_is_read_and_typed(
    #[case] file: &str,
    #[case] name: &str,
    #[case] password: &str,
    #[case] description: &str,
) {
    let types: Vec<passbolt_sdk::types::ResourceType> =
        serde_json::from_value(data::resource_types()).unwrap();

    let parsed = import::parse_csv(file, &types, true, REFERENCE.into()).unwrap();

    let (resource, resource_type) = &parsed.resources[0];
    assert_eq!(resource.name, name);
    assert_eq!(resource.secret_clear, password);
    assert_eq!(
        resource.description.as_deref().unwrap_or_default(),
        description
    );
    assert_eq!(resource_type.slug, "v5-default");
    assert!(parsed.errors.is_empty(), "{:?}", parsed.errors);
}
