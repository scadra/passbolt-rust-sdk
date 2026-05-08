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

//! The resource type an imported row gets, chosen as the browser extension chooses it: the
//! type storing the most of what the row holds, all its required secret fields given.

use crate::error::PassboltError;
use crate::types::ResourceType;

use super::external::ExternalResource;

/// The secret fields of each type the browser extension knows, then the required ones, as
/// its schemas define them; password-string types are never chosen.
const SECRET_FIELDS: [(&str, &[&str], &[&str]); 9] = [
    (
        "password-and-description",
        &["password", "description"],
        &["password"],
    ),
    (
        "password-description-totp",
        &["password", "description", "totp"],
        &["password", "totp"],
    ),
    ("totp", &["totp"], &["totp"]),
    (
        "v5-default",
        &["password", "description", "custom_fields"],
        &["password"],
    ),
    (
        "v5-default-with-totp",
        &["password", "description", "totp", "custom_fields"],
        &["password", "totp"],
    ),
    ("v5-totp-standalone", &["totp"], &["totp"]),
    ("v5-custom-fields", &["custom_fields"], &["custom_fields"]),
    ("v5-note", &["description"], &["description"]),
    ("v5-pin-code", &["pin_code", "description"], &["pin_code"]),
];

const PASSWORD_STRING_SLUGS: [&str; 2] = ["password-string", "v5-password-string"];

/// Why a row did not get the type that fits it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeWarning {
    /// Closest type: some required secret field is missing.
    Partial,
    /// No type stores what the row holds: the default one.
    Default,
}

impl TypeWarning {
    /// The browser extension's title and detail of the warning.
    #[must_use]
    pub const fn texts(self) -> (&'static str, &'static str) {
        match self {
            Self::Partial => (
                "Resource partially imported",
                "We used the closest resource type supported.",
            ),
            Self::Default => (
                "Imported with default content type",
                "No resource type associated to this row.",
            ),
        }
    }
}

/// The types an import uses: those of the default version (v5 or v4) whose slug the browser
/// extension knows, in the server's order.
#[must_use]
pub fn importable_types(types: &[ResourceType], v5: bool) -> Vec<ResourceType> {
    types
        .iter()
        .filter(|resource_type| resource_type.is_v5() == v5)
        .filter(|resource_type| {
            PASSWORD_STRING_SLUGS.contains(&resource_type.slug.as_str())
                || SECRET_FIELDS
                    .iter()
                    .any(|(slug, _, _)| *slug == resource_type.slug)
        })
        .cloned()
        .collect()
}

/// The secret fields `resource` holds, named as in the type schemas.
fn held_fields(resource: &ExternalResource) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if !resource.secret_clear.is_empty() {
        fields.push("password");
    }
    if resource
        .description
        .as_deref()
        .is_some_and(|text| !text.is_empty())
    {
        fields.push("description");
    }
    if resource.totp.is_some() {
        fields.push("totp");
    }
    if !resource.custom_fields.is_empty() {
        fields.push("custom_fields");
    }
    if resource
        .pin_code
        .as_deref()
        .is_some_and(|code| !code.is_empty())
    {
        fields.push("pin_code");
    }
    fields
}

struct Score<'a> {
    slug: &'a str,
    value: usize,
    missing_required: usize,
}

fn scores<'a>(resource: &ExternalResource, types: &'a [ResourceType]) -> Vec<Score<'a>> {
    types
        .iter()
        .filter_map(|resource_type| {
            let (_, fields, required) = SECRET_FIELDS
                .iter()
                .find(|(slug, _, _)| *slug == resource_type.slug)?;
            let mut held = held_fields(resource);
            // A TOTP with a description stands for a password-description-TOTP resource.
            let totp_type = matches!(
                resource_type.slug.as_str(),
                "password-description-totp" | "v5-default-with-totp"
            );
            if totp_type && held.contains(&"totp") && held.contains(&"description") {
                held.push("password");
            }
            let stored: Vec<&str> = held
                .iter()
                .copied()
                .filter(|field| fields.contains(field))
                .collect();
            Some(Score {
                slug: &resource_type.slug,
                value: stored.len(),
                missing_required: required
                    .iter()
                    .filter(|field| !stored.contains(field))
                    .count(),
            })
        })
        .collect()
}

/// A v5 PIN code: a password of 4 to 12 digits with nothing but a name, a description, a
/// folder, an expiry or an icon beside it, when the server has the type.
pub fn read_pin_code(resource: &mut ExternalResource, types: &[ResourceType]) {
    let has_pin_code_type = types
        .iter()
        .any(|resource_type| resource_type.slug == "v5-pin-code");
    let secret = &resource.secret_clear;
    let pin_like =
        (4..=12).contains(&secret.len()) && secret.chars().all(|digit| digit.is_ascii_digit());
    let extra_content = resource
        .username
        .as_deref()
        .is_some_and(|text| !text.is_empty())
        || resource.uris.iter().any(|uri| !uri.is_empty())
        || resource.totp.is_some()
        || !resource.custom_fields.is_empty()
        || resource.has_other_values;
    if has_pin_code_type && pin_like && !extra_content {
        resource.pin_code = Some(std::mem::take(&mut resource.secret_clear));
    }
}

/// The type `resource` is imported as, among `types` (see [`importable_types`]), with the
/// warning to report when it is not a full match.
pub fn choose(
    resource: &ExternalResource,
    types: &[ResourceType],
    v5: bool,
) -> Result<(ResourceType, Option<TypeWarning>), PassboltError> {
    let by_slug = |slug: &str| {
        types
            .iter()
            .find(|resource_type| resource_type.slug == slug)
            .cloned()
    };
    let scores = scores(resource, types);
    let supported = || scores.iter().filter(|score| score.value > 0);
    // The highest value; on a tie, the first in the server's order, as a stable sort keeps it.
    let full = supported()
        .filter(|score| score.missing_required == 0)
        .fold(None::<&Score>, |best, score| match best {
            Some(best) if best.value >= score.value => Some(best),
            _ => Some(score),
        });
    if let Some(resource_type) = full.and_then(|score| by_slug(score.slug)) {
        return Ok((resource_type, None));
    }
    let partial = supported().fold(None::<&Score>, |best, score| match best {
        Some(best) if best.missing_required <= score.missing_required => Some(best),
        _ => Some(score),
    });
    if let Some(resource_type) = partial.and_then(|score| by_slug(score.slug)) {
        return Ok((resource_type, Some(TypeWarning::Partial)));
    }
    let default_slug = if v5 {
        "v5-default"
    } else {
        "password-and-description"
    };
    by_slug(default_slug)
        .map(|resource_type| (resource_type, Some(TypeWarning::Default)))
        .ok_or_else(|| {
            PassboltError::InvalidArgument("No resource type associated to this row.".into())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exchange::external::totp_with_defaults;

    fn types(slugs: &[&str]) -> Vec<ResourceType> {
        slugs
            .iter()
            .map(|slug| ResourceType {
                id: format!("{slug}-id"),
                slug: (*slug).to_string(),
                name: None,
                definition: None,
            })
            .collect()
    }

    const V5: [&str; 9] = [
        "v5-default",
        "v5-password-string",
        "v5-default-with-totp",
        "v5-totp-standalone",
        "v5-custom-fields",
        "v5-note",
        "v5-pin-code",
        "password-and-description",
        "totp",
    ];

    fn chosen(resource: &ExternalResource) -> (String, Option<TypeWarning>) {
        let types = importable_types(&types(&V5), true);
        let (resource_type, warning) = choose(resource, &types, true).unwrap();
        (resource_type.slug, warning)
    }

    #[test]
    fn test_only_the_types_of_the_default_version_are_used() {
        let slugs: Vec<String> = importable_types(&types(&V5), true)
            .into_iter()
            .map(|resource_type| resource_type.slug)
            .collect();

        assert!(
            slugs.iter().all(|slug| slug.starts_with("v5-")),
            "{slugs:?}"
        );
    }

    #[test]
    fn test_a_password_is_a_default_resource() {
        let resource = ExternalResource {
            secret_clear: "p".into(),
            ..ExternalResource::default()
        };

        assert_eq!(chosen(&resource), ("v5-default".into(), None));
    }

    #[test]
    fn test_a_password_and_a_totp_need_the_totp_type() {
        let resource = ExternalResource {
            secret_clear: "p".into(),
            totp: Some(totp_with_defaults("A".into(), None, None, None)),
            ..ExternalResource::default()
        };

        assert_eq!(chosen(&resource), ("v5-default-with-totp".into(), None));
    }

    #[test]
    fn test_a_description_alone_is_a_note() {
        let resource = ExternalResource {
            description: Some("note".into()),
            ..ExternalResource::default()
        };

        assert_eq!(chosen(&resource), ("v5-note".into(), None));
    }

    #[test]
    fn test_a_totp_with_a_description_counts_as_a_password() {
        let resource = ExternalResource {
            description: Some("d".into()),
            totp: Some(totp_with_defaults("A".into(), None, None, None)),
            ..ExternalResource::default()
        };

        assert_eq!(chosen(&resource), ("v5-default-with-totp".into(), None));
    }

    #[test]
    fn test_an_empty_row_gets_the_default_type_with_a_warning() {
        assert_eq!(
            chosen(&ExternalResource::default()),
            ("v5-default".into(), Some(TypeWarning::Default))
        );
    }

    #[rstest::rstest]
    #[case("1234", None, Some("1234"))]
    #[case("123456789012", None, Some("123456789012"))]
    #[case("123", None, None)]
    #[case("12a4", None, None)]
    #[case("1234", Some("ada"), None)]
    fn test_a_short_number_alone_is_a_pin_code(
        #[case] secret: &str,
        #[case] username: Option<&str>,
        #[case] pin_code: Option<&str>,
    ) {
        let mut resource = ExternalResource {
            secret_clear: secret.into(),
            username: username.map(String::from),
            ..ExternalResource::default()
        };

        read_pin_code(&mut resource, &types(&V5));

        assert_eq!(resource.pin_code.as_deref(), pin_code);
    }
}
