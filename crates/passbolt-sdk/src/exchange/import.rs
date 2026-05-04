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

//! Importing a file as the browser extension does: everything goes into a new folder named
//! `import-<date>`, the folders of the file below it, each resource personal to the user.

use std::collections::HashMap;

use serde::Serialize;

use crate::client::PassboltSdk;
use crate::error::PassboltError;
use crate::http::HttpClient;
use crate::resource::create::{create_resource, NewResource};
use crate::types::ResourceType;

use super::csv;
use super::external::{child_path, resolve_escaped_name, split_folder_path, ExternalResource};
use super::formats;
use super::resource_type::{choose, importable_types, read_pin_code};

/// What to create besides the resources.
#[derive(Debug, Clone, Copy)]
pub struct ImportOptions {
    /// Create the folders of the file, below the import folder.
    pub folders: bool,
    /// Tag every imported resource with the name of the import.
    pub tags: bool,
}

/// A row, folder or resource that was not imported as it is, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportIssue {
    pub title: String,
    pub detail: String,
    /// The name of the resource, or the path of the folder.
    pub item: String,
}

/// A file read, ready to import.
#[derive(Debug, Clone)]
pub struct ParsedImport {
    /// `import-<YYYYMMDDHHMMSS>`: the import folder and tag.
    pub reference: String,
    /// Each resource with its type, its folder path starting with the import folder.
    pub resources: Vec<(ExternalResource, ResourceType)>,
    /// The paths of the folders to create, the import folder first.
    pub folders: Vec<String>,
    pub errors: Vec<ImportIssue>,
    pub warnings: Vec<ImportIssue>,
}

/// What an import did.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ImportReport {
    pub reference: String,
    pub resources: usize,
    pub folders: usize,
    /// The folder holding the import, when folders were created.
    pub folder_id: Option<String>,
    /// The tag of the imported resources, when they were tagged.
    pub tag: Option<String>,
    pub errors: Vec<ImportIssue>,
    pub warnings: Vec<ImportIssue>,
}

/// The name of an import made at `now`: `import-20240131235959`.
#[must_use]
pub fn reference(now: chrono::DateTime<chrono::Utc>) -> String {
    format!("import-{}", now.format("%Y%m%d%H%M%S"))
}

/// Read a CSV file of a known format; `types` are the server's resource types.
pub fn parse_csv(
    text: &str,
    types: &[ResourceType],
    v5: bool,
    reference: String,
) -> Result<ParsedImport, PassboltError> {
    let table = csv::read(text);
    let format = formats::detect(&table.columns).ok_or_else(|| {
        PassboltError::InvalidArgument("This csv format is not supported.".into())
    })?;
    let rows = table
        .rows
        .iter()
        .map(|row| (format.parse)(format, row).map_err(|error| (row_name(format, row), error)));
    Ok(assemble(rows, types, v5, reference))
}

fn row_name(format: &formats::CsvFormat, row: &csv::Row) -> String {
    format
        .column("name")
        .and_then(|column| row.get(column))
        .cloned()
        .unwrap_or_default()
}

/// The resources read, typed, under the import folder, with the folders their paths need.
pub fn assemble(
    rows: impl Iterator<Item = Result<ExternalResource, (String, PassboltError)>>,
    types: &[ResourceType],
    v5: bool,
    reference: String,
) -> ParsedImport {
    let types = importable_types(types, v5);
    let mut parsed = ParsedImport {
        reference,
        resources: Vec::new(),
        folders: Vec::new(),
        errors: Vec::new(),
        warnings: Vec::new(),
    };
    for row in rows {
        let mut resource = match row {
            Ok(resource) => resource,
            Err((name, error)) => {
                parsed
                    .errors
                    .push(issue("Cannot parse resource", &error, name));
                continue;
            }
        };
        read_pin_code(&mut resource, &types);
        let resource = resource.normalized();
        match choose(&resource, &types, v5) {
            Ok((resource_type, warning)) => {
                if let Some(warning) = warning {
                    let (title, detail) = warning.texts();
                    parsed.warnings.push(ImportIssue {
                        title: title.into(),
                        detail: detail.into(),
                        item: resource.name.clone(),
                    });
                }
                parsed.resources.push((resource, resource_type));
            }
            Err(error) => {
                let name = resource.name.clone();
                parsed
                    .errors
                    .push(issue("Cannot parse resource", &error, name));
            }
        }
    }
    for (resource, _) in &parsed.resources {
        push_path(&mut parsed.folders, &resource.folder_parent_path);
    }
    let reference = parsed.reference.clone();
    parsed.folders = std::iter::once(reference.clone())
        .chain(
            parsed
                .folders
                .iter()
                .map(|path| child_path(&reference, path)),
        )
        .collect();
    for (resource, _) in &mut parsed.resources {
        resource.folder_parent_path = child_path(&reference, &resource.folder_parent_path);
    }
    parsed
}

fn issue(title: &str, error: &PassboltError, item: String) -> ImportIssue {
    ImportIssue {
        title: title.into(),
        detail: error.to_string(),
        item,
    }
}

/// Add `path` and the folders above it to `folders`, each once.
fn push_path(folders: &mut Vec<String>, path: &str) {
    if path.is_empty() {
        return;
    }
    let mut cursor = String::new();
    for name in split_folder_path(path) {
        cursor = child_path(&cursor, &name);
        if !folders.contains(&cursor) {
            folders.push(cursor.clone());
        }
    }
}

/// The depth of a folder path: 0 for a folder at the root.
fn depth(path: &str) -> usize {
    split_folder_path(path).len() - 1
}

/// The name of the folder at `path`, its `/` unescaped, and the path of its parent.
fn name_and_parent(path: &str) -> (String, String) {
    let mut names = split_folder_path(path);
    let name = names.pop().unwrap_or_default();
    (resolve_escaped_name(&name), names.join("/"))
}

const PASSWORD_TYPES: [&str; 6] = [
    "password-string",
    "password-and-description",
    "password-description-totp",
    "v5-default",
    "v5-default-with-totp",
    "v5-password-string",
];
const TOTP_TYPES: [&str; 4] = [
    "password-description-totp",
    "totp",
    "v5-default-with-totp",
    "v5-totp-standalone",
];
const SECRET_DESCRIPTION_TYPES: [&str; 6] = [
    "password-and-description",
    "password-description-totp",
    "v5-default",
    "v5-default-with-totp",
    "v5-note",
    "v5-pin-code",
];
const CUSTOM_FIELDS_TYPES: [&str; 3] = ["v5-default", "v5-default-with-totp", "v5-custom-fields"];

/// The resource to create for `resource` of type `resource_type`, split as the browser
/// extension splits it.
///
/// A password-string type keeps the description in its metadata, the others in their secret
/// when they have one, else it goes.
#[must_use]
pub fn new_resource(
    resource: &ExternalResource,
    resource_type: &ResourceType,
    folder_parent_id: Option<String>,
) -> NewResource {
    let slug = resource_type.slug.as_str();
    let description = resource.description.clone().filter(|text| !text.is_empty());
    let password_string = matches!(slug, "password-string" | "v5-password-string");
    let secret_description = SECRET_DESCRIPTION_TYPES.contains(&slug);
    let (metadata_description, note) = match () {
        () if password_string => (description, None),
        () if secret_description && resource_type.is_v5() => (None, description),
        () if secret_description => (description, None),
        () => (None, None),
    };
    let uris = if resource_type.is_v5() {
        resource.uris.clone()
    } else {
        resource.uris.first().cloned().into_iter().collect()
    };
    NewResource {
        resource_type: Some(slug.to_string()),
        name: resource.name.clone(),
        username: resource.username.clone().filter(|text| !text.is_empty()),
        uris,
        description: metadata_description,
        note,
        password: PASSWORD_TYPES
            .contains(&slug)
            .then(|| resource.secret_clear.clone()),
        totp: resource.totp.clone().filter(|_| TOTP_TYPES.contains(&slug)),
        pin_code: resource.pin_code.clone().filter(|_| slug == "v5-pin-code"),
        icon: resource.icon.clone(),
        custom_fields: if CUSTOM_FIELDS_TYPES.contains(&slug) {
            resource.custom_fields.clone()
        } else {
            Vec::new()
        },
        folder_parent_id,
        expired: resource.expired.clone(),
        without_folder_permissions: true,
        ..NewResource::default()
    }
}

/// Import `parsed`: its folders, its resources, then its tag.
///
/// The folders (with `options.folders`) are created depth after depth, the tag with
/// `options.tags`. A folder that fails takes what it holds with it; a resource that fails is
/// reported.
pub async fn import<H: HttpClient>(
    client: &PassboltSdk<H>,
    parsed: ParsedImport,
    options: ImportOptions,
) -> Result<ImportReport, PassboltError> {
    let mut report = ImportReport {
        reference: parsed.reference.clone(),
        errors: parsed.errors,
        warnings: parsed.warnings,
        ..ImportReport::default()
    };
    let mut resources = parsed.resources;
    let mut folder_ids: HashMap<String, String> = HashMap::new();
    if options.folders {
        let mut folders = parsed.folders;
        folders.sort_by_key(|path| depth(path));
        for path in folders {
            let (name, parent_path) = name_and_parent(&path);
            if !parent_path.is_empty() && !folder_ids.contains_key(&parent_path) {
                // Its parent failed: it went with it.
                continue;
            }
            let parent_id = folder_ids.get(&parent_path).cloned();
            match crate::folder::create::create_folder(client, &name, parent_id.as_deref()).await {
                Ok(folder) => {
                    folder_ids.insert(path, folder.id);
                    report.folders += 1;
                }
                Err(error) => {
                    report
                        .errors
                        .push(issue("Cannot import folder", &error, path.clone()));
                    resources.retain(|(resource, _)| {
                        resource.folder_parent_path != path
                            && !resource.folder_parent_path.starts_with(&format!("{path}/"))
                    });
                }
            }
        }
        report.folder_id = folder_ids.get(&parsed.reference).cloned();
    }
    let mut created_ids = Vec::new();
    for (resource, resource_type) in &resources {
        let folder_parent_id = folder_ids.get(&resource.folder_parent_path).cloned();
        let new_resource = new_resource(resource, resource_type, folder_parent_id);
        match create_resource(client, &new_resource).await {
            Ok(created) => created_ids.push(created.id),
            Err(error) => {
                report.errors.push(issue(
                    "Cannot import resource",
                    &error,
                    resource.name.clone(),
                ));
            }
        }
    }
    report.resources = created_ids.len();
    if options.tags && !created_ids.is_empty() {
        let tag = vec![parsed.reference.clone()];
        for id in &created_ids {
            if let Err(error) = client.update_resource_tags(id, &tag).await {
                report
                    .errors
                    .push(issue("Cannot tag resource", &error, id.clone()));
            }
        }
        report.tag = Some(parsed.reference);
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn types() -> Vec<ResourceType> {
        [
            "v5-default",
            "v5-note",
            "v5-pin-code",
            "v5-default-with-totp",
        ]
        .iter()
        .map(|slug| ResourceType {
            id: format!("{slug}-id"),
            slug: (*slug).to_string(),
            name: None,
            definition: None,
        })
        .collect()
    }

    fn parsed(text: &str) -> ParsedImport {
        parse_csv(text, &types(), true, "import-20240131235959".into()).unwrap()
    }

    #[test]
    fn test_the_reference_is_the_date_of_the_import() {
        let now = chrono::DateTime::parse_from_rfc3339("2024-01-31T23:59:59.123Z")
            .unwrap()
            .to_utc();

        assert_eq!(reference(now), "import-20240131235959");
    }

    #[test]
    fn test_every_folder_goes_below_the_import_folder() {
        let parsed = parsed(
            "Title,Password,Group\r\nA,p,Work/Mail\r\nB,p,Work\r\nC,p,\r\nD,p,Home/a / b\r\n",
        );

        assert_eq!(
            parsed.folders,
            [
                "import-20240131235959",
                "import-20240131235959/Work",
                "import-20240131235959/Work/Mail",
                "import-20240131235959/Home",
                "import-20240131235959/Home/a / b",
            ]
        );
        let paths: Vec<&str> = parsed
            .resources
            .iter()
            .map(|(resource, _)| resource.folder_parent_path.as_str())
            .collect();
        assert_eq!(
            paths,
            [
                "import-20240131235959/Work/Mail",
                "import-20240131235959/Work",
                "import-20240131235959",
                "import-20240131235959/Home/a / b",
            ]
        );
    }

    #[test]
    fn test_a_folder_name_is_created_without_its_escaping() {
        assert_eq!(
            name_and_parent("import-1/Home/a / b"),
            ("a/b".to_string(), "import-1/Home".to_string())
        );
    }

    #[test]
    fn test_a_row_that_cannot_be_read_is_reported() {
        let parsed = parsed("Title,URL,Password,TOTP\r\nA,,p,not-a-uri\r\nB,,p,\r\n");

        assert_eq!(parsed.resources.len(), 1);
        assert_eq!(parsed.errors[0].title, "Cannot parse resource");
        assert_eq!(parsed.errors[0].item, "A");
    }

    #[test]
    fn test_an_unknown_file_is_refused() {
        let error = parse_csv("a,b\r\n1,2\r\n", &types(), true, "import-1".into())
            .err()
            .unwrap();

        assert!(error.to_string().contains("not supported"), "{error}");
    }

    fn typed(slug: &str) -> ResourceType {
        ResourceType {
            id: format!("{slug}-id"),
            slug: slug.into(),
            name: None,
            definition: None,
        }
    }

    #[rstest::rstest]
    #[case::v5_description_becomes_the_note("v5-default", None, Some("d"))]
    #[case::v4_description_goes_to_the_secret("password-and-description", Some("d"), None)]
    #[case::password_string_keeps_it_in_the_metadata("v5-password-string", Some("d"), None)]
    #[case::a_totp_type_loses_it("v5-totp-standalone", None, None)]
    fn test_the_description_goes_where_the_type_keeps_it(
        #[case] slug: &str,
        #[case] description: Option<&str>,
        #[case] note: Option<&str>,
    ) {
        let resource = ExternalResource {
            name: "x".into(),
            description: Some("d".into()),
            ..ExternalResource::default()
        };

        let new = new_resource(&resource, &typed(slug), None);

        assert_eq!(new.description.as_deref(), description);
        assert_eq!(new.note.as_deref(), note);
    }
}
