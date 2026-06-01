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

//! `Bitwarden` CSV (`csv-bitwarden`): the URIs separated by commas, the TOTP as a URI or its secret key.

use crate::error::PassboltError;
use crate::exchange::csv::Row;
use crate::exchange::external::ExternalResource;

use super::{compose_row, parse_row, CsvFormat, Totp, Uris, Written};

const MAPPING: &[(&str, &str)] = &[
    ("name", "name"),
    ("username", "login_username"),
    ("uris", "login_uri"),
    ("secret_clear", "login_password"),
    ("description", "notes"),
    ("folder_parent_path", "folder"),
    ("totp", "login_totp"),
];

pub const FORMAT: CsvFormat = CsvFormat {
    name: "csv-bitwarden",
    delimiter: ',',
    mapping: MAPPING,
    export_mapping: MAPPING,
    parse,
    compose,
};

fn parse(format: &CsvFormat, row: &Row) -> Result<ExternalResource, PassboltError> {
    parse_row(format, row, Uris::Split, Totp::UriOrSecretKey)
}

fn compose(format: &CsvFormat, resource: &ExternalResource) -> Vec<String> {
    compose_row(format, resource, Written::AllUris)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exchange::external::totp_with_defaults;

    fn row(cells: &[(&str, &str)]) -> Row {
        cells
            .iter()
            .map(|(column, value)| ((*column).to_string(), (*value).to_string()))
            .collect()
    }

    fn expected() -> ExternalResource {
        ExternalResource {
            name: "Password 1".into(),
            username: Some("Username 1".into()),
            uris: vec![
                "https://url1.com".into(),
                "https://url2.com".into(),
                "https://url3.com".into(),
            ],
            secret_clear: "Secret 1".into(),
            description: Some("Description 1".into()),
            folder_parent_path: "Folder 1".into(),
            ..ExternalResource::default()
        }
    }

    #[test]
    fn test_the_example_row_of_the_browser_extension_is_read() {
        let resource = (FORMAT.parse)(
            &FORMAT,
            &row(&[
                ("name", "Password 1"),
                ("login_username", "Username 1"),
                (
                    "login_uri",
                    "https://url1.com,https://url2.com,https://url3.com",
                ),
                ("login_password", "Secret 1"),
                ("notes", "Description 1"),
                ("folder", "Folder 1"),
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
                "Password 1",
                "Username 1",
                "https://url1.com,https://url2.com,https://url3.com",
                "Secret 1",
                "Description 1",
                "Folder 1",
                ""
            ]
        );
    }

    #[test]
    fn test_a_totp_secret_key_alone_gets_the_defaults() {
        let resource = (FORMAT.parse)(
            &FORMAT,
            &row(&[("name", "x"), ("login_totp", "JBSWY3DPEHPK3PXP")]),
        )
        .unwrap();

        assert_eq!(
            resource.totp,
            Some(totp_with_defaults("JBSWY3DPEHPK3PXP", None, None, None))
        );
    }
}
