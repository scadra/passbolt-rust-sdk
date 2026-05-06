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

//! The CSV formats of other password managers, as the browser extension reads and writes them.

mod keepass;
mod lastpass;
mod one_password;

use crate::error::PassboltError;

use super::csv::Row;
use super::external::{parse_totp_uri, totp_with_defaults, ExternalResource};
use crate::types::TotpData;

/// A CSV format: its columns, and how a row becomes a resource and back.
pub struct CsvFormat {
    /// The browser extension's name of the format, `csv-kdbx`…
    pub name: &'static str,
    /// The delimiter written; a file read gets its delimiter guessed.
    pub delimiter: char,
    /// Each resource field and the column it is read from.
    pub mapping: &'static [(&'static str, &'static str)],
    /// Each resource field and the column it is written to, in the order of the columns.
    pub export_mapping: &'static [(&'static str, &'static str)],
    pub parse: fn(&Self, &Row) -> Result<ExternalResource, PassboltError>,
    pub compose: fn(&Self, &ExternalResource) -> Vec<String>,
}

/// How the URI column is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Uris {
    /// One URI, when the cell holds one.
    WhenSet,
    /// One URI, empty when the cell is; a file without the column is refused.
    Always,
    /// The URIs of the cell, separated by commas.
    Split,
}

/// How the TOTP column is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Totp {
    /// An `otpauth://` URI.
    Uri,
    /// The secret key alone.
    SecretKey,
    /// An `otpauth://` URI, else the secret key alone.
    UriOrSecretKey,
}

/// How the URIs and the TOTP are written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Written {
    /// The first URI and the TOTP URI.
    FirstUri,
    /// All the URIs separated by commas, and the TOTP URI.
    AllUris,
    /// The first URI and the TOTP secret key.
    TotpSecretKey,
}

/// The formats, in the order the browser extension tries them when reading.
pub const FORMATS: [&CsvFormat; 3] = [&one_password::FORMAT, &keepass::FORMAT, &lastpass::FORMAT];

/// The format named `name`.
pub fn named(name: &str) -> Result<&'static CsvFormat, PassboltError> {
    FORMATS
        .iter()
        .copied()
        .find(|format| format.name == name)
        .ok_or_else(|| {
            let names: Vec<&str> = FORMATS.iter().map(|format| format.name).collect();
            PassboltError::InvalidArgument(format!(
                "This csv format is not supported: {name} (formats: {})",
                names.join(", ")
            ))
        })
}

impl CsvFormat {
    /// The column of `field`.
    #[must_use]
    pub fn column(&self, field: &str) -> Option<&'static str> {
        self.mapping
            .iter()
            .find(|(name, _)| *name == field)
            .map(|(_, column)| *column)
    }

    /// The columns written, in order.
    #[must_use]
    pub fn columns(&self) -> Vec<&'static str> {
        self.export_mapping
            .iter()
            .map(|(_, column)| *column)
            .collect()
    }

    /// How well a file with these `columns` fits: none without a name and a password column,
    /// else 2 plus one per username, URI, description and folder column.
    #[must_use]
    pub fn score(&self, columns: &[String]) -> usize {
        let has = |field: &str| {
            self.column(field)
                .is_some_and(|column| columns.iter().any(|name| name == column))
        };
        if !has("name") || !has("secret_clear") {
            return 0;
        }
        2 + ["username", "uris", "description", "folder_parent_path"]
            .into_iter()
            .filter(|field| has(field))
            .count()
    }
}

/// The format a file with these `columns` is read with: the best scored, the first on a tie.
#[must_use]
pub fn detect(columns: &[String]) -> Option<&'static CsvFormat> {
    FORMATS
        .iter()
        .copied()
        .fold(None::<(&CsvFormat, usize)>, |best, format| {
            let score = format.score(columns);
            match best {
                Some((_, best_score)) if best_score >= score => best,
                _ if score > 0 => Some((format, score)),
                _ => best,
            }
        })
        .map(|(format, _)| format)
}

/// A row read field by field through the mapping; a value in a column the resource does not
/// keep is noted (see [`ExternalResource::has_other_values`]).
pub fn parse_row(
    format: &CsvFormat,
    row: &Row,
    uris: Uris,
    totp: Totp,
) -> Result<ExternalResource, PassboltError> {
    let mut resource = ExternalResource::default();
    for (field, column) in format.mapping {
        let cell = row.get(*column);
        if *field == "uris" && uris == Uris::Always {
            let uri = cell.ok_or_else(|| {
                PassboltError::InvalidArgument(format!("The column {column} is missing"))
            })?;
            resource.uris = vec![uri.clone()];
            continue;
        }
        let Some(value) = cell.filter(|value| !value.is_empty()) else {
            continue;
        };
        match *field {
            "name" => resource.name.clone_from(value),
            "username" => resource.username = Some(value.clone()),
            "uris" if uris == Uris::Split => {
                resource.uris = value.split(',').map(String::from).collect();
            }
            "uris" => resource.uris = vec![value.clone()],
            "secret_clear" => resource.secret_clear.clone_from(value),
            "description" => resource.description = Some(value.clone()),
            "folder_parent_path" => resource.folder_parent_path.clone_from(value),
            "totp" => resource.totp = Some(read_totp(value, totp)?),
            _ => resource.has_other_values = true,
        }
    }
    Ok(resource)
}

fn read_totp(value: &str, totp: Totp) -> Result<TotpData, PassboltError> {
    let is_uri = value.to_lowercase().starts_with("otpauth://");
    match totp {
        Totp::Uri => parse_totp_uri(value),
        Totp::UriOrSecretKey if is_uri => parse_totp_uri(value),
        Totp::SecretKey | Totp::UriOrSecretKey => {
            Ok(totp_with_defaults(value.to_string(), None, None, None))
        }
    }
}

/// A row read as the `KeePass` CSV format reads it: values when set, the TOTP from its URI.
pub fn parse_by_mapping(format: &CsvFormat, row: &Row) -> Result<ExternalResource, PassboltError> {
    parse_row(format, row, Uris::WhenSet, Totp::Uri)
}

/// The text of `field` of `resource`, empty when unset or not a resource field.
#[must_use]
pub fn field_text(resource: &ExternalResource, field: &str, written: Written) -> String {
    match field {
        "name" => resource.name.clone(),
        "username" => resource.username.clone().unwrap_or_default(),
        "uris" if written == Written::AllUris => resource.uris.join(","),
        "uris" => resource.uris.first().cloned().unwrap_or_default(),
        "secret_clear" => resource.secret_clear.clone(),
        "description" => resource.description.clone().unwrap_or_default(),
        "folder_parent_path" => resource.folder_parent_path.clone(),
        "totp" if written == Written::TotpSecretKey => resource
            .totp
            .as_ref()
            .and_then(|totp| totp.secret_key.clone())
            .unwrap_or_default(),
        "totp" => resource.totp_uri().unwrap_or_default(),
        _ => String::new(),
    }
}

/// A row written field by field through the export mapping.
#[must_use]
pub fn compose_row(
    format: &CsvFormat,
    resource: &ExternalResource,
    written: Written,
) -> Vec<String> {
    format
        .export_mapping
        .iter()
        .map(|(field, _)| field_text(resource, field, written))
        .collect()
}

/// A row written as the `KeePass` CSV format writes it: the first URI, the TOTP URI.
#[must_use]
pub fn compose_by_mapping(format: &CsvFormat, resource: &ExternalResource) -> Vec<String> {
    compose_row(format, resource, Written::FirstUri)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn columns(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_string()).collect()
    }

    #[test]
    fn test_a_file_without_a_password_column_fits_no_format() {
        assert!(detect(&columns(&["Title", "Username"])).is_none());
    }

    #[test]
    fn test_keepass_columns_are_detected() {
        let format = detect(&columns(&[
            "Title", "Username", "URL", "Password", "Notes", "Group",
        ]));

        assert_eq!(format.map(|format| format.name), Some("csv-kdbx"));
    }

    #[test]
    fn test_an_unknown_format_name_is_refused() {
        let error = named("csv-unknown").err().unwrap().to_string();

        assert!(error.contains("csv-kdbx"), "{error}");
    }
}
