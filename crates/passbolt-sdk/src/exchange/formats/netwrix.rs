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

//! Netwrix Password Secure CSV (`csv-netwrix`): `;`-separated; the email stands for a missing username, the tags are not read.

use crate::error::PassboltError;
use crate::exchange::csv::Row;
use crate::exchange::external::ExternalResource;

use super::{compose_row, CsvFormat, Written};

const MAPPING: &[(&str, &str)] = &[
    ("tags", "DataTags"),
    ("name", "Description"),
    ("username", "User name"),
    ("secret_clear", "Password"),
    ("uris", "Internet address"),
    ("email", "Email address"),
];

pub const FORMAT: CsvFormat = CsvFormat {
    name: "csv-netwrix",
    delimiter: ';',
    mapping: MAPPING,
    export_mapping: MAPPING,
    parse,
    compose,
};

/// The name, username and password when set, the address as the URI; the email address
/// stands for a missing username.
#[allow(clippy::unnecessary_wraps)] // The signature of every format's parser.
fn parse(format: &CsvFormat, row: &Row) -> Result<ExternalResource, PassboltError> {
    let cell = |field: &str| {
        format
            .column(field)
            .and_then(|column| row.get(column))
            .filter(|value| !value.is_empty())
            .cloned()
    };
    Ok(ExternalResource {
        name: cell("name").unwrap_or_default(),
        username: cell("username").or_else(|| cell("email")),
        uris: cell("uris").into_iter().collect(),
        secret_clear: cell("secret_clear").unwrap_or_default(),
        ..ExternalResource::default()
    })
}

fn compose(format: &CsvFormat, resource: &ExternalResource) -> Vec<String> {
    compose_row(format, resource, Written::FirstUri)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(cells: &[(&str, &str)]) -> Row {
        cells
            .iter()
            .map(|(column, value)| ((*column).to_string(), (*value).to_string()))
            .collect()
    }

    fn expected() -> ExternalResource {
        ExternalResource {
            name: "Google".into(),
            username: Some("Hans.Mustermann".into()),
            uris: vec!["https://www.google.de".into()],
            secret_clear: "Secret 1".into(),
            ..ExternalResource::default()
        }
    }

    #[test]
    fn test_the_example_row_of_the_browser_extension_is_read() {
        let resource = (FORMAT.parse)(
            &FORMAT,
            &row(&[
                ("DataTags", "Tag1|Tag2|Tag3"),
                ("Description", "Google"),
                ("User name", "Hans.Mustermann"),
                ("Password", "Secret 1"),
                ("Internet address", "https://www.google.de"),
                ("Email address", "hans@mustermann.de"),
            ]),
        )
        .unwrap();

        assert_eq!(resource, expected());
    }

    #[test]
    fn test_a_resource_is_written_as_the_browser_extension_writes_it() {
        assert_eq!(
            (FORMAT.compose)(&FORMAT, &expected()),
            [
                "",
                "Google",
                "Hans.Mustermann",
                "Secret 1",
                "https://www.google.de",
                ""
            ]
        );
    }
}
