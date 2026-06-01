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

//! `LastPass` CSV (`csv-lastpass`): the TOTP as its secret key alone.

use crate::error::PassboltError;
use crate::exchange::csv::Row;
use crate::exchange::external::ExternalResource;

use super::{compose_row, parse_row, CsvFormat, Totp, Uris, Written};

const MAPPING: &[(&str, &str)] = &[
    ("uris", "url"),
    ("username", "username"),
    ("secret_clear", "password"),
    ("totp", "totp"),
    ("description", "extra"),
    ("name", "name"),
    ("folder_parent_path", "grouping"),
    ("fav", "fav"),
];

pub const FORMAT: CsvFormat = CsvFormat {
    name: "csv-lastpass",
    delimiter: ',',
    mapping: MAPPING,
    export_mapping: MAPPING,
    parse,
    compose,
};

fn parse(format: &CsvFormat, row: &Row) -> Result<ExternalResource, PassboltError> {
    parse_row(format, row, Uris::WhenSet, Totp::SecretKey)
}

fn compose(format: &CsvFormat, resource: &ExternalResource) -> Vec<String> {
    compose_row(format, resource, Written::TotpSecretKey)
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
            uris: vec!["https://url1.com".into()],
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
                ("username", "Username 1"),
                ("url", "https://url1.com"),
                ("password", "Secret 1"),
                ("extra", "Description 1"),
                ("grouping", "Folder 1"),
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
                "https://url1.com",
                "Username 1",
                "Secret 1",
                "",
                "Description 1",
                "Password 1",
                "Folder 1",
                ""
            ]
        );
    }

    #[test]
    fn test_a_totp_secret_key_alone_gets_the_defaults() {
        let resource = (FORMAT.parse)(
            &FORMAT,
            &row(&[("name", "x"), ("totp", "JBSWY3DPEHPK3PXP")]),
        )
        .unwrap();

        assert_eq!(
            resource.totp,
            Some(totp_with_defaults("JBSWY3DPEHPK3PXP", None, None, None))
        );
    }
}
