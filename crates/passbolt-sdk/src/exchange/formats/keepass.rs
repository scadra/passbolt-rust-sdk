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

//! `KeePass` CSV (`csv-kdbx`): the folder in `Group`, the TOTP as an `otpauth://` URI.

use super::{compose_by_mapping, parse_by_mapping, CsvFormat};

const MAPPING: &[(&str, &str)] = &[
    ("name", "Title"),
    ("username", "Username"),
    ("uris", "URL"),
    ("secret_clear", "Password"),
    ("description", "Notes"),
    ("folder_parent_path", "Group"),
    ("totp", "TOTP"),
];

pub const FORMAT: CsvFormat = CsvFormat {
    name: "csv-kdbx",
    delimiter: ',',
    mapping: MAPPING,
    export_mapping: MAPPING,
    parse: parse_by_mapping,
    compose: compose_by_mapping,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exchange::csv::Row;
    use crate::exchange::external::{totp_with_defaults, ExternalResource};

    fn row(cells: &[(&str, &str)]) -> Row {
        cells
            .iter()
            .map(|(column, value)| ((*column).to_string(), (*value).to_string()))
            .collect()
    }

    #[test]
    fn test_a_row_reads_every_column() {
        let resource = (FORMAT.parse)(
            &FORMAT,
            &row(&[
                ("Title", "Password 1"),
                ("Username", "Username 1"),
                ("URL", "https://url1.com"),
                ("Password", "Secret 1"),
                ("Notes", "Description 1"),
                ("Group", "Folder 1"),
                (
                    "TOTP",
                    "otpauth://totp/x?secret=ABC&algorithm=SHA256&digits=8&period=60",
                ),
            ]),
        )
        .unwrap();

        assert_eq!(
            resource,
            ExternalResource {
                name: "Password 1".into(),
                username: Some("Username 1".into()),
                uris: vec!["https://url1.com".into()],
                secret_clear: "Secret 1".into(),
                description: Some("Description 1".into()),
                folder_parent_path: "Folder 1".into(),
                totp: Some(totp_with_defaults(
                    "ABC".into(),
                    Some("SHA256".into()),
                    Some(8),
                    Some(60)
                )),
                ..ExternalResource::default()
            }
        );
    }

    #[test]
    fn test_empty_cells_are_left_unset() {
        let resource = (FORMAT.parse)(&FORMAT, &row(&[("Title", "x"), ("Notes", "")])).unwrap();

        assert_eq!(resource.description, None);
    }

    #[test]
    fn test_a_resource_is_written_in_the_column_order() {
        let resource = ExternalResource {
            name: "Password 1".into(),
            username: Some("Username 1".into()),
            uris: vec!["https://url1.com".into(), "https://url2.com".into()],
            secret_clear: "Secret 1".into(),
            folder_parent_path: "Folder 1".into(),
            ..ExternalResource::default()
        };

        assert_eq!(
            (FORMAT.compose)(&FORMAT, &resource),
            [
                "Password 1",
                "Username 1",
                "https://url1.com",
                "Secret 1",
                "",
                "Folder 1",
                ""
            ]
        );
    }
}
