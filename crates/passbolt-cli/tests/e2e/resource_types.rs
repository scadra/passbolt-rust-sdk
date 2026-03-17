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

use crate::common::{
    admin_id, create_folder, create_resource, ids, metadata_key_type, resource_column, run,
    run_json, run_json_as, run_text, share_with_user_id, unique_name, Account, Cleanup, ADMIN,
};

const TOTP_KEY: &str = "JBSWY3DPEHPK3PXP";

/// Create a resource of type `slug` with `args`, then read it back.
fn create_and_get(slug: &str, args: &[&str]) -> (Cleanup, serde_json::Value) {
    let name = unique_name(slug);
    let mut create_args = vec!["create", "resource", "--type", slug, "--name", &name];
    create_args.extend_from_slice(args);
    let resource = Cleanup::new("resource", &run_json(&create_args));

    let fetched = run_json(&["get", "resource", "--id", &resource.id]);

    assert_eq!(fetched["name"], name.as_str(), "{slug}");
    (resource, fetched)
}

#[test]
fn every_creatable_type_reads_back() {
    let cases: [(&str, &[&str], bool); 10] = [
        (
            "password-string",
            &["--password", "p", "--uri", "https://e2e.test"],
            false,
        ),
        (
            "password-and-description",
            &["--password", "p", "--description", "d"],
            false,
        ),
        (
            "password-description-totp",
            &["--password", "p", "--totp-key", TOTP_KEY],
            false,
        ),
        ("totp", &["--totp-key", TOTP_KEY], false),
        (
            "v5-default",
            &[
                "--password",
                "p",
                "--uri",
                "https://a.test",
                "--uri",
                "https://b.test",
            ],
            true,
        ),
        (
            "v5-default-with-totp",
            &["--password", "p", "--totp-key", TOTP_KEY],
            true,
        ),
        ("v5-totp-standalone", &["--totp-key", TOTP_KEY], true),
        ("v5-note", &["--note", "a secret note"], true),
        ("v5-pin-code", &["--pin-code", "123456"], true),
        (
            "v5-default",
            &["--password", "p", "--username", "e2e", "--description", "d"],
            true,
        ),
    ];

    for (slug, args, v5) in cases {
        let (resource, fetched) = create_and_get(slug, args);

        assert_eq!(
            resource_column(Account::User, &resource.id, "resource_type"),
            slug,
            "{fetched}"
        );
        assert_eq!(
            metadata_key_type(Account::User, &resource.id).is_some(),
            v5,
            "{slug}: {fetched}"
        );
    }
}

#[test]
fn v5_default_keeps_the_password_username_and_first_uri() {
    let (_resource, fetched) = create_and_get(
        "v5-default",
        &[
            "--password",
            "s3cr3t",
            "--username",
            "e2e",
            "--uri",
            "https://a.test",
            "--uri",
            "https://b.test",
        ],
    );

    assert_eq!(fetched["password"], "s3cr3t");
    assert_eq!(fetched["username"], "e2e");
    assert_eq!(fetched["uri"], "https://a.test");
}

#[test]
fn v5_password_string_cannot_be_created() {
    let output = crate::common::passbolt()
        .args([
            "create",
            "resource",
            "--type",
            "v5-password-string",
            "--name",
            "x",
            "--password",
            "p",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("read-only"));
}

#[test]
fn v5_updated_password_reads_back() {
    let resource = create_resource(&unique_name("v5"), "first", &["--type", "v5-default"]);

    run(&[
        "update",
        "resource",
        "--id",
        &resource.id,
        "--password",
        "second",
    ]);

    assert_eq!(
        run_json(&["get", "resource", "--id", &resource.id])["password"],
        "second"
    );
}

#[test]
fn v5_personal_resource_can_be_shared() {
    let resource = create_resource(&unique_name("v5"), "p", &["--type", "v5-default"]);

    run(&[
        "share",
        "resource",
        "--id",
        &resource.id,
        "--user",
        &share_with_user_id(),
        "--type",
        "1",
    ]);
}

#[test]
fn v5_resource_is_found_by_name() {
    let name = unique_name("v5");
    let resource = create_resource(&name, "p", &["--type", "v5-default"]);

    let found = run_json(&["list", "resource", "--search", &name]);

    assert_eq!(ids(&found), [resource.id.as_str()]);
}

#[test]
fn v5_personal_resource_shared_with_a_user_reads_back_for_them() {
    let name = unique_name("v5");
    let resource = create_resource(&name, "shared-password", &["--type", "v5-default"]);

    run(&[
        "share",
        "resource",
        "--id",
        &resource.id,
        "--type",
        "1",
        "--user",
        &admin_id(),
    ]);

    let as_recipient = run_json_as(ADMIN, &["get", "resource", "--id", &resource.id]);
    assert_eq!(as_recipient["name"], name.as_str());
    assert_eq!(as_recipient["password"], "shared-password");
    assert_eq!(
        metadata_key_type(ADMIN, &resource.id).as_deref(),
        Some("shared_key")
    );
}

#[test]
fn moving_with_the_folder_permissions_shares_like_the_folder() {
    let folder = create_folder(&unique_name("shared-folder"), &[]);
    run(&[
        "share",
        "folder",
        "--id",
        &folder.id,
        "--type",
        "1",
        "--user",
        &admin_id(),
    ]);
    let resource = create_resource(
        &unique_name("v5"),
        "folder-password",
        &["--type", "v5-default"],
    );

    run(&[
        "move",
        "resource",
        "--id",
        &resource.id,
        "--folder-parent-id",
        &folder.id,
        "--with-folder-permissions",
    ]);

    let as_recipient = run_json_as(ADMIN, &["get", "resource", "--id", &resource.id]);
    assert_eq!(as_recipient["password"], "folder-password");
}

const CUSTOM_FIELD_ID: &str = "0f7b6a51-0000-4000-8000-0000000000c1";

#[test]
fn custom_fields_note_and_pin_code_read_back_in_get() {
    let custom_fields = format!(
        r#"custom_fields=[{{"id":"{CUSTOM_FIELD_ID}","type":"text","metadata_key":"Account"}}]"#
    );
    let secret_custom_fields = format!(
        r#"custom_fields=[{{"id":"{CUSTOM_FIELD_ID}","type":"text","secret_value":"42"}}]"#
    );
    let (fields, _) = create_and_get(
        "v5-custom-fields",
        &[
            "--field",
            &custom_fields,
            "--secret-field",
            &secret_custom_fields,
        ],
    );
    let (note, _) = create_and_get("v5-note", &["--note", "a secret note"]);
    let (pin, _) = create_and_get("v5-pin-code", &["--pin-code", "246810"]);

    let shown = run_text(&["get", "resource", "--id", &fields.id]);
    assert!(shown.contains("Account") && shown.contains("42"), "{shown}");
    assert!(run_text(&["get", "resource", "--id", &note.id]).contains("a secret note"));
    assert!(run_text(&["get", "resource", "--id", &pin.id]).contains("246810"));

    let as_json = run_json(&["get", "resource", "--id", &fields.id]);
    assert_eq!(
        as_json["metadata"]["custom_fields"][0]["metadata_key"],
        "Account"
    );
    assert_eq!(as_json["secret"]["custom_fields"][0]["secret_value"], "42");
}

#[test]
fn a_field_updates_without_touching_the_others() {
    let resource = create_resource(
        &unique_name("v5"),
        "p",
        &["--type", "v5-default", "--username", "kept"],
    );

    run(&[
        "update",
        "resource",
        "--id",
        &resource.id,
        "--field",
        r#"icon={"type":"keepass-icon-set","value":7}"#,
    ]);

    let fetched = run_json(&["get", "resource", "--id", &resource.id]);
    assert_eq!(fetched["metadata"]["icon"]["value"], 7);
    assert_eq!(fetched["username"], "kept");
    assert_eq!(fetched["password"], "p");
}

#[test]
fn v5_totp_generates_a_code() {
    let (resource, _) = create_and_get(
        "v5-default-with-totp",
        &["--password", "p", "--totp-key", TOTP_KEY],
    );

    let code = run_json(&["get", "totp", "--id", &resource.id]);

    assert_eq!(code["code"].as_str().map(str::len), Some(6), "{code}");
}

#[test]
fn list_json_shows_the_requested_decrypted_columns() {
    let name = unique_name("v5");
    let _resource = create_resource(&name, "listed-password", &["--type", "v5-default"]);

    let listed = run_json(&[
        "list", "resource", "--search", &name, "-c", "Name", "-c", "Password", "-c", "Type",
    ]);

    assert_eq!(
        listed,
        serde_json::json!([{"name": name, "password": "listed-password", "resource_type": "v5-default"}])
    );
}

#[test]
fn an_unknown_column_is_refused() {
    let output = crate::common::passbolt()
        .args(["list", "resource", "-c", "colour"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown column: \"colour\""));
}

#[test]
fn secret_fields_alone_create_a_resource_of_the_matching_type() {
    let cases = [
        ("password=s3cr3t", "v5-default", "password", "s3cr3t"),
        ("description=a note", "v5-note", "note", "a note"),
    ];
    for (secret_field, slug, read_field, read_value) in cases {
        let name = unique_name("secret-field");
        let created = run_json(&[
            "create",
            "resource",
            "--name",
            &name,
            "--secret-field",
            secret_field,
        ]);
        let resource = Cleanup::new("resource", &created);

        let fetched = run_json(&["get", "resource", "--id", &resource.id]);

        assert_eq!(
            resource_column(Account::User, &resource.id, "resource_type"),
            slug,
            "{fetched}"
        );
        let value = if read_field == "note" {
            &fetched["secret"]["description"]
        } else {
            &fetched[read_field]
        };
        assert_eq!(value, read_value, "{fetched}");
    }
}
