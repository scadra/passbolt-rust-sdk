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

//! `import` and `export csv`, as the browser extension imports and exports files.

use std::path::Path;

use serde_json::Value;

use crate::common::{
    block_on, create_folder, create_resource, passbolt, resource_column, run_json, sdk_login,
    unique_name, Account,
};

/// The import folder, deleted with what it holds when dropped.
struct ImportFolder(String);

impl Drop for ImportFolder {
    fn drop(&mut self) {
        let _ = passbolt()
            .args(["delete", "folder", "--id", &self.0, "--cascade"])
            .output();
    }
}

fn import(file: &Path, extra_args: &[&str]) -> (Value, ImportFolder) {
    let mut args = vec!["import", "-f", file.to_str().unwrap()];
    args.extend_from_slice(extra_args);
    let report = run_json(&args);
    let folder = ImportFolder(report["folder_id"].as_str().unwrap_or_default().to_string());
    (report, folder)
}

/// The resources named after `prefix`: name, folder and password of each.
fn listed(prefix: &str) -> Vec<Value> {
    let mut listed = run_json(&[
        "list",
        "resource",
        "--filter",
        &format!("name^={prefix}"),
        "-c",
        "id",
        "-c",
        "name",
        "-c",
        "folder_parent_id",
        "-c",
        "password",
    ])
    .as_array()
    .unwrap()
    .clone();
    listed.sort_by_key(|resource| resource["name"].as_str().unwrap_or_default().to_string());
    listed
}

fn folder_name(id: &str) -> String {
    run_json(&["get", "folder", "--id", id])["name"]
        .as_str()
        .unwrap()
        .to_string()
}

fn parent_of(folder_id: &str) -> String {
    let folders = run_json(&["list", "folder", "-c", "id", "-c", "folder_parent_id"]);
    folders
        .as_array()
        .unwrap()
        .iter()
        .find(|folder| folder["id"] == folder_id)
        .map(|folder| folder["folder_parent_id"].as_str().unwrap().to_string())
        .unwrap()
}

/// The passwords of the resources in `folder_id` and in its folders.
fn passwords_below(folder_id: &str) -> Vec<String> {
    let folders = run_json(&["list", "folder", "-c", "id", "-c", "folder_parent_id"]);
    let children = folders
        .as_array()
        .unwrap()
        .iter()
        .filter(|folder| folder["folder_parent_id"] == folder_id)
        .map(|folder| folder["id"].as_str().unwrap().to_string());
    std::iter::once(folder_id.to_string())
        .chain(children)
        .flat_map(|id| {
            run_json(&["list", "resource", "--folder", &id, "-c", "password"])
                .as_array()
                .unwrap()
                .iter()
                .map(|resource| resource["password"].as_str().unwrap().to_string())
                .collect::<Vec<_>>()
        })
        .collect()
}

#[test]
fn a_keepass_csv_file_is_imported_into_its_folders() {
    let prefix = unique_name("import");
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("keepass.csv");
    std::fs::write(
        &file,
        format!(
            "Title,Username,URL,Password,Notes,Group,TOTP\r\n\
             {prefix} one,ada,https://e2e.test,secret-one,note one,Work,\r\n\
             {prefix} two,,,secret-two,,Work/Mail,otpauth://totp/x?secret=JBSWY3DPEHPK3PXP\r\n\
             {prefix} three,,,1234,,,\r\n"
        ),
    )
    .unwrap();

    let (report, import_folder) = import(&file, &[]);

    assert_eq!(report["resources"], 3, "{report}");
    assert_eq!(report["folders"], 3, "{report}");
    assert_eq!(report["errors"], serde_json::json!([]), "{report}");
    let reference = report["reference"].as_str().unwrap();
    assert_eq!(folder_name(&import_folder.0), reference);
    let resources = listed(&prefix);
    let [one, three, two] = resources.as_slice() else {
        panic!("{resources:?}");
    };
    assert_eq!(one["password"], "secret-one");
    assert_eq!(
        folder_name(one["folder_parent_id"].as_str().unwrap()),
        "Work"
    );
    let mail = two["folder_parent_id"].as_str().unwrap();
    assert_eq!(folder_name(mail), "Mail");
    assert_eq!(folder_name(&parent_of(mail)), "Work");
    assert_eq!(three["folder_parent_id"], import_folder.0.as_str());
    let tags = block_on(sdk_login(Account::User).get_tags()).unwrap();
    assert!(tags.iter().any(|tag| tag.slug == reference), "{tags:?}");
}

#[test]
fn a_password_of_four_digits_alone_is_imported_as_a_pin_code() {
    let prefix = unique_name("pin");
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("keepass.csv");
    // KeePass columns: `Title,Password` alone is read as 1Password, which needs a `Url` column.
    std::fs::write(&file, format!("Title,URL,Password\r\n{prefix},,1234\r\n")).unwrap();

    let (_, _folder) = import(&file, &["--no-tags"]);

    let id = listed(&prefix)[0]["id"].as_str().unwrap().to_string();
    let resource_type = resource_column(Account::User, &id, "resource_type");
    assert!(
        resource_type == "v5-pin-code" || resource_type == "password-and-description",
        "{resource_type}"
    );
}

#[test]
fn a_file_of_an_unknown_format_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("unknown.csv");
    std::fs::write(&file, "a,b\r\n1,2\r\n").unwrap();

    passbolt()
        .args(["import", "-f", file.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "This csv format is not supported.",
        ));
}

#[test]
fn a_folder_exports_as_the_browser_extension_writes_keepass_csv() {
    let folder_name = unique_name("export");
    let folder = create_folder(&folder_name, &[]);
    let name = unique_name("exported");
    let _resource = create_resource(
        &name,
        "exported-password",
        &[
            "--type",
            "v5-default-with-totp",
            "--username",
            "ada",
            "--uri",
            "https://a.test",
            "--description",
            "exported description",
            "--totp-key",
            "JBSWY3DPEHPK3PXP",
            "--folder-parent-id",
            &folder.id,
        ],
    );
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("export.csv");

    run_json(&[
        "export",
        "csv",
        "--format",
        "csv-kdbx",
        "--folder-id",
        &folder.id,
        "-f",
        file.to_str().unwrap(),
    ]);

    let label = format!("{name}:ada").replace(':', "%3A");
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        format!(
            "\"Title\",\"Username\",\"URL\",\"Password\",\"Notes\",\"Group\",\"TOTP\"\r\n\
             \"{name}\",\"ada\",\"https://a.test\",\"exported-password\",\
             \"exported description\",\"{folder_name}\",\
             \"otpauth://totp/{label}?secret=JBSWY3DPEHPK3PXP\
             &issuer=https%253A%252F%252Fa.test&algorithm=SHA1&digits=6&period=30\""
        )
    );
}

#[test]
fn an_exported_folder_imports_back() {
    let folder_name = unique_name("roundtrip");
    let folder = create_folder(&folder_name, &[]);
    let prefix = unique_name("again");
    let _first = create_resource(
        &format!("{prefix} first"),
        "first-password",
        &["--folder-parent-id", &folder.id],
    );
    let _second = create_resource(
        &format!("{prefix} second"),
        "second-password",
        &["--folder-parent-id", &folder.id],
    );
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("export.csv");
    run_json(&[
        "export",
        "csv",
        "--folder-id",
        &folder.id,
        "-f",
        file.to_str().unwrap(),
    ]);

    let (report, _import_folder) = import(&file, &["--no-tags"]);

    assert_eq!(report["resources"], 2, "{report}");
    let copies: Vec<Value> = listed(&prefix)
        .into_iter()
        .filter(|resource| resource["folder_parent_id"] != folder.id.as_str())
        .collect();
    let passwords: Vec<&Value> = copies.iter().map(|copy| &copy["password"]).collect();
    assert_eq!(passwords, ["first-password", "second-password"]);
    let copy_folder = copies[0]["folder_parent_id"].as_str().unwrap();
    assert_eq!(self::folder_name(copy_folder), folder_name);
}

// Each CSV format: a folder exported as the browser extension writes it, then imported.

#[rstest::rstest]
#[case::lastpass("csv-lastpass", "\"url\",\"username\",\"password\",\"totp\",\"extra\",\"name\",\"grouping\",\"fav\"", "\"<uri>\",\"ada\",\"<password>\",\"<totp_key>\",\"<description>\",\"<name>\",\"<folder>\",\"\"")]
#[case::one_password(
    "csv-1password",
    "\"Title\",\"Username\",\"Url\",\"Password\",\"Notes\",\"Type\"",
    "\"<name>\",\"ada\",\"<uri>\",\"<password>\",\"<description>\",\"<folder>\""
)]
#[case::chromium(
    "csv-chromium",
    "\"name\",\"url\",\"username\",\"password\"",
    "\"<name>\",\"<uri>\",\"ada\",\"<password>\""
)]
#[case::bitwarden("csv-bitwarden", "\"name\",\"login_username\",\"login_uri\",\"login_password\",\"notes\",\"folder\",\"login_totp\"", "\"<name>\",\"ada\",\"<uri>\",\"<password>\",\"<description>\",\"<folder>\",\"<totp_uri>\"")]
fn a_folder_exports_and_imports_back(
    #[case] format: &str,
    #[case] header: &str,
    #[case] row: &str,
) {
    let folder_name = unique_name("format");
    let folder = create_folder(&folder_name, &[]);
    let name = unique_name(format);
    let _resource = create_resource(
        &name,
        "format-password",
        &[
            "--type",
            "v5-default-with-totp",
            "--username",
            "ada",
            "--uri",
            "https://a.test",
            "--description",
            "format description",
            "--totp-key",
            "JBSWY3DPEHPK3PXP",
            "--folder-parent-id",
            &folder.id,
        ],
    );
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("export.csv");

    run_json(&[
        "export",
        "csv",
        "--format",
        format,
        "--folder-id",
        &folder.id,
        "-f",
        file.to_str().unwrap(),
    ]);

    let totp_uri = format!(
        "otpauth://totp/{}?secret=JBSWY3DPEHPK3PXP&issuer=https%253A%252F%252Fa.test&algorithm=SHA1&digits=6&period=30",
        format!("{name}:ada").replace(':', "%3A")
    );
    let expected_row = row
        .replace("<name>", &name)
        .replace("<uri>", "https://a.test")
        .replace("<password>", "format-password")
        .replace("<description>", "format description")
        .replace("<folder>", &folder_name)
        .replace("<totp_key>", "JBSWY3DPEHPK3PXP")
        .replace("<totp_uri>", &totp_uri);
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        format!("{header}\r\n{expected_row}")
    );

    let (report, _import_folder) = import(&file, &["--no-tags"]);
    assert_eq!(report["resources"], 1, "{report}");
    // Looked up by folder: some formats name the resource after its URI.
    let imported = passwords_below(report["folder_id"].as_str().unwrap());
    assert_eq!(imported, ["format-password"]);
}
