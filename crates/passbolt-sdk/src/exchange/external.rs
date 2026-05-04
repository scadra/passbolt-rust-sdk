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

//! Resources and folders as files hold them, as the browser extension reads and writes them:
//! folders as `/`-separated paths, the secret in clear, the TOTP as an `otpauth://` URI.

use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde_json::Value;

use crate::error::PassboltError;
use crate::types::{CustomField, TotpData};

/// The name of a resource without one.
pub const DEFAULT_RESOURCE_NAME: &str = "(no name)";

/// A resource read from or written to a file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExternalResource {
    pub name: String,
    pub username: Option<String>,
    pub uris: Vec<String>,
    pub description: Option<String>,
    /// The password, or the PIN code of an exported PIN code resource.
    pub secret_clear: String,
    /// The folders above it, from the root: `Folder/Sub folder`.
    pub folder_parent_path: String,
    pub totp: Option<TotpData>,
    pub expired: Option<String>,
    pub icon: Option<Value>,
    pub custom_fields: Vec<CustomField>,
    pub pin_code: Option<String>,
    /// A column the resource does not keep holds a value: such a row is no PIN code.
    pub has_other_values: bool,
}

impl ExternalResource {
    /// The resource as the browser extension keeps it: a name, a cleaned folder path.
    #[must_use]
    pub fn normalized(mut self) -> Self {
        if self.name.is_empty() {
            DEFAULT_RESOURCE_NAME.clone_into(&mut self.name);
        }
        self.folder_parent_path = sanitize_path(&self.folder_parent_path);
        self
    }

    /// The `otpauth://totp/` URI of its TOTP, as the browser extension writes it.
    #[must_use]
    pub fn totp_uri(&self) -> Option<String> {
        let totp = self.totp.as_ref()?;
        let label = match &self.username {
            Some(username) if !username.is_empty() => format!("{}:{username}", self.name),
            _ => self.name.clone(),
        };
        let mut parameters = vec![("secret", totp.secret_key.clone().unwrap_or_default())];
        if let Some(uri) = self.uris.first() {
            // The issuer is URI-encoded, then encoded again as a query parameter.
            parameters.push(("issuer", encode_uri_component(uri)));
        }
        parameters.push(("algorithm", totp.algorithm.clone().unwrap_or_default()));
        parameters.push(("digits", totp.digits.unwrap_or_default().to_string()));
        parameters.push(("period", totp.period.unwrap_or_default().to_string()));
        let query = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(parameters)
            .finish();
        Some(format!(
            "otpauth://totp/{}?{query}",
            encode_uri_component(&label)
        ))
    }
}

/// The TOTP of an `otpauth://` URI, percent-decoded first as the browser extension does;
/// SHA1, 6 digits and 30 seconds unless the URI says otherwise.
pub fn parse_totp_uri(text: &str) -> Result<TotpData, PassboltError> {
    let invalid = || PassboltError::InvalidArgument(format!("Invalid TOTP URI: {text}"));
    let decoded = percent_decode_str(text)
        .decode_utf8()
        .map_err(|_| invalid())?;
    let uri = url::Url::parse(&decoded).map_err(|_| invalid())?;
    let parameter = |name: &str| {
        uri.query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    };
    Ok(totp_with_defaults(
        parameter("secret").unwrap_or_default(),
        parameter("algorithm"),
        parameter("digits").and_then(|digits| leading_number(&digits)),
        parameter("period").and_then(|period| leading_number(&period)),
    ))
}

/// A TOTP with the browser extension's defaults for what is missing (SHA1, 6, 30).
#[must_use]
pub fn totp_with_defaults(
    secret_key: String,
    algorithm: Option<String>,
    digits: Option<u64>,
    period: Option<u64>,
) -> TotpData {
    TotpData {
        secret_key: Some(secret_key),
        algorithm: Some(
            algorithm
                .filter(|algorithm| !algorithm.is_empty())
                .unwrap_or_else(|| "SHA1".into()),
        ),
        digits: Some(
            digits
                .filter(|digits| *digits != 0)
                .and_then(|digits| u32::try_from(digits).ok())
                .unwrap_or(6),
        ),
        period: Some(period.filter(|period| *period != 0).unwrap_or(30)),
        issuer: None,
    }
}

/// The number a text starts with, as JavaScript's `parseInt(text, 10)` reads it.
fn leading_number(text: &str) -> Option<u64> {
    let digits: String = text
        .trim_start()
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// What JavaScript's `encodeURIComponent` leaves as it is.
const URI_COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'!')
    .remove(b'~')
    .remove(b'*')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')');

/// JavaScript's `encodeURIComponent`.
#[must_use]
pub fn encode_uri_component(text: &str) -> String {
    utf8_percent_encode(text, URI_COMPONENT).to_string()
}

/// Whether the character at `index` of `characters` is a space.
fn is_space(characters: &[char], index: Option<usize>) -> bool {
    index.and_then(|index| characters.get(index)) == Some(&' ')
}

/// A folder path cleaned as the browser extension cleans it.
///
/// In three steps: a run of `/` at either end becomes one; a `/` at either end goes, unless a
/// space is beside it; a run of `/` between names without a space beside it becomes one.
#[must_use]
pub fn sanitize_path(path: &str) -> String {
    remove_runs_between_names(&remove_end_slashes(&shorten_end_runs(path)))
}

fn shorten_end_runs(path: &str) -> String {
    let leading = path
        .chars()
        .take_while(|character| *character == '/')
        .count();
    let characters: Vec<char> = path.chars().collect();
    let mut shortened: Vec<char> = if leading >= 2 {
        std::iter::once('/')
            .chain(characters[leading..].iter().copied())
            .collect()
    } else {
        characters
    };
    // The leading run took the whole text: nothing is left at its end.
    if leading < path.chars().count() {
        let trailing = shortened
            .iter()
            .rev()
            .take_while(|character| **character == '/')
            .count();
        if trailing >= 2 {
            shortened.truncate(shortened.len() - trailing);
            shortened.push('/');
        }
    }
    shortened.into_iter().collect()
}

fn remove_end_slashes(path: &str) -> String {
    let characters: Vec<char> = path.chars().collect();
    let length = characters.len();
    let drop_first = characters.first() == Some(&'/') && !is_space(&characters, Some(1));
    let drop_last = length > 1
        && characters.last() == Some(&'/')
        && !is_space(&characters, Some(length - 2))
        && !(drop_first && length == 1);
    characters
        .iter()
        .enumerate()
        .filter(|(index, _)| {
            let dropped = (drop_first && *index == 0) || (drop_last && *index == length - 1);
            !dropped
        })
        .map(|(_, character)| *character)
        .collect()
}

fn remove_runs_between_names(path: &str) -> String {
    let characters: Vec<char> = path.chars().collect();
    let mut cleaned = String::with_capacity(path.len());
    let mut index = 0;
    while index < characters.len() {
        if characters[index] == '/' && !is_space(&characters, index.checked_sub(1)) {
            let run = characters[index..]
                .iter()
                .take_while(|character| **character == '/')
                .count();
            // The longest run of two or more not followed by a space.
            let taken = (2..=run)
                .rev()
                .find(|length| !is_space(&characters, Some(index + length)));
            if let Some(length) = taken {
                cleaned.push('/');
                index += length;
                continue;
            }
        }
        cleaned.push(characters[index]);
        index += 1;
    }
    cleaned
}

/// The names of a folder path: split on each `/` without a space beside it.
#[must_use]
pub fn split_folder_path(path: &str) -> Vec<String> {
    let characters: Vec<char> = path.chars().collect();
    let mut names = Vec::new();
    let mut name = String::new();
    for (index, character) in characters.iter().enumerate() {
        let separator = *character == '/'
            && !is_space(&characters, index.checked_sub(1))
            && !is_space(&characters, Some(index + 1));
        if separator {
            names.push(std::mem::take(&mut name));
        } else {
            name.push(*character);
        }
    }
    names.push(name);
    names
}

/// A folder name written in a path, as the browser extension escapes it: trimmed, a leading
/// `/` followed by a space, a trailing one preceded by a space, the others between spaces.
#[must_use]
pub fn escape_name(name: &str) -> String {
    let mut characters: Vec<char> = name.trim().chars().collect();
    if characters.first() == Some(&'/') {
        characters.splice(0..1, ['/', ' ']);
    }
    if characters.last() == Some(&'/') {
        let last = characters.len() - 1;
        characters.splice(last.., [' ', '/']);
    }
    // `(.)/(.)` replaced by `$1 / $2`, each match taking its three characters.
    let mut escaped = String::with_capacity(characters.len() + 8);
    let mut index = 0;
    while index < characters.len() {
        escaped.push(characters[index]);
        if index + 2 < characters.len() && characters[index + 1] == '/' {
            escaped.push_str(" / ");
            escaped.push(characters[index + 2]);
            index += 3;
        } else {
            index += 1;
        }
    }
    escaped
}

/// A folder name read from a path: ` / `, ` /` and `/ ` become `/` again.
#[must_use]
pub fn resolve_escaped_name(name: &str) -> String {
    let mut resolved = String::with_capacity(name.len());
    let mut rest = name;
    while let Some(character) = rest.chars().next() {
        let pattern = [" / ", " /", "/ "]
            .into_iter()
            .find(|pattern| rest.starts_with(pattern));
        if let Some(pattern) = pattern {
            resolved.push('/');
            rest = &rest[pattern.len()..];
        } else {
            resolved.push(character);
            rest = &rest[character.len_utf8()..];
        }
    }
    resolved
}

/// The path of `name` in `parent_path`; either may be empty.
#[must_use]
pub fn child_path(parent_path: &str, name: &str) -> String {
    match (parent_path.is_empty(), name.is_empty()) {
        (true, _) => name.to_string(),
        (false, true) => parent_path.to_string(),
        (false, false) => format!("{parent_path}/{name}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[rstest::rstest]
    #[case("/root/folder/", "root/folder")]
    #[case("//root//folder//", "root/folder")]
    #[case("root/folder", "root/folder")]
    #[case("/ root", "/ root")]
    #[case("root /", "root /")]
    #[case("a / b", "a / b")]
    #[case("a // b", "a // b")]
    #[case("a//// b", "a// b")]
    #[case("///", "")]
    #[case("/", "")]
    #[case("", "")]
    fn test_paths_are_cleaned_as_the_browser_extension_cleans_them(
        #[case] path: &str,
        #[case] cleaned: &str,
    ) {
        assert_eq!(sanitize_path(path), cleaned);
    }

    #[rstest::rstest]
    #[case("root/folder", &["root", "folder"])]
    #[case("root/a / b", &["root", "a / b"])]
    #[case("single", &["single"])]
    fn test_paths_split_on_slashes_without_spaces(#[case] path: &str, #[case] names: &[&str]) {
        assert_eq!(split_folder_path(path), names);
    }

    #[rstest::rstest]
    #[case("a/b", "a / b")]
    #[case("/a", "/ a")]
    #[case("a/", "a /")]
    #[case("/", "/ ")]
    #[case("a//b", "a / /b")]
    #[case("  plain  ", "plain")]
    fn test_folder_names_are_escaped_as_the_browser_extension_escapes_them(
        #[case] name: &str,
        #[case] escaped: &str,
    ) {
        assert_eq!(escape_name(name), escaped);
    }

    #[rstest::rstest]
    #[case("a / b", "a/b")]
    #[case("/ a", "/a")]
    #[case("a /", "a/")]
    #[case("a  / b", "a /b")]
    fn test_escaped_names_resolve_back(#[case] escaped: &str, #[case] name: &str) {
        assert_eq!(resolve_escaped_name(escaped), name);
    }

    fn resource_with_totp() -> ExternalResource {
        ExternalResource {
            name: "Git hub".into(),
            username: Some("ada@passbolt.com".into()),
            uris: vec!["https://github.com/login?x=1&y=2".into()],
            totp: Some(totp_with_defaults(
                "JBSWY3DPEHPK3PXP".into(),
                None,
                None,
                None,
            )),
            ..ExternalResource::default()
        }
    }

    #[test]
    fn test_the_totp_uri_is_written_as_the_browser_extension_writes_it() {
        assert_eq!(
            resource_with_totp().totp_uri().unwrap(),
            "otpauth://totp/Git%20hub%3Aada%40passbolt.com?secret=JBSWY3DPEHPK3PXP\
             &issuer=https%253A%252F%252Fgithub.com%252Flogin%253Fx%253D1%2526y%253D2\
             &algorithm=SHA1&digits=6&period=30"
        );
    }

    #[test]
    fn test_a_written_totp_uri_reads_back() {
        let uri = resource_with_totp().totp_uri().unwrap();

        assert_eq!(
            parse_totp_uri(&uri).unwrap(),
            resource_with_totp().totp.unwrap()
        );
    }

    #[test]
    fn test_a_totp_uri_gets_the_defaults_it_lacks() {
        let totp = parse_totp_uri("otpauth://totp/x?secret=ABC&digits=8").unwrap();

        assert_eq!(totp, totp_with_defaults("ABC".into(), None, Some(8), None));
    }

    #[test]
    fn test_a_resource_without_a_name_gets_the_default_one() {
        let resource = ExternalResource {
            folder_parent_path: "/a/b/".into(),
            ..ExternalResource::default()
        }
        .normalized();

        assert_eq!(resource.name, DEFAULT_RESOURCE_NAME);
        assert_eq!(resource.folder_parent_path, "a/b");
    }
}
