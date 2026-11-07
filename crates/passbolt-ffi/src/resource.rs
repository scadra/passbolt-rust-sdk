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

//! The decrypted view of a resource, and the resources to create or change, as records: the
//! fields every resource type shares are typed, the others travel as JSON objects.

use chrono::{DateTime, Utc};
use passbolt_sdk::resource::{create, update, view};
use passbolt_sdk::types;
use serde_json::{Map, Value};

use crate::error::PassboltError;
use crate::types::TotpData;

fn to_iso(date_time: Option<DateTime<Utc>>) -> Option<String> {
    date_time.map(|date_time| date_time.to_rfc3339())
}

fn json_object(json: Option<String>, what: &str) -> Result<Map<String, Value>, PassboltError> {
    json.map_or_else(
        || Ok(Map::new()),
        |json| {
            serde_json::from_str(&json).map_err(|error| PassboltError::InvalidArgument {
                reason: format!("{what} is not a JSON object: {error}"),
            })
        },
    )
}

/// A resource with its v5 metadata decrypted, and its secret when it was asked for.
#[derive(uniffi::Record)]
pub struct ResourceView {
    pub id: String,
    pub name: String,
    pub username: String,
    /// The first of `uris`.
    pub uri: String,
    pub uris: Vec<String>,
    /// The v5 metadata description, else the v4 one.
    pub description: String,
    pub folder_parent_id: Option<String>,
    /// The type slug; `None` for a type the server does not list.
    pub resource_type: Option<String>,
    pub resource_type_id: Option<String>,
    pub personal: Option<bool>,
    /// `user_key` (personal) or `shared_key` for v5 resources.
    pub metadata_key_type: Option<String>,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub expired: Option<String>,
    pub password: Option<String>,
    pub totp: Option<TotpData>,
    /// The decrypted v5 metadata, or the v4 fields, as a JSON object: the icon and custom
    /// fields among them.
    pub metadata_json: String,
    /// The decrypted secret as a JSON object, when it was asked for and decrypted.
    pub secret_json: Option<String>,
    /// Why the metadata or the secret could not be decrypted.
    pub error: Option<String>,
}

impl From<view::ResourceView> for ResourceView {
    fn from(view: view::ResourceView) -> Self {
        let totp = view
            .secret
            .as_ref()
            .and_then(|secret| secret.get("totp"))
            .and_then(|totp| serde_json::from_value::<types::TotpData>(totp.clone()).ok())
            .map(TotpData::from);
        Self {
            id: view.id,
            name: view.name,
            username: view.username,
            uri: view.uri,
            uris: view.uris,
            description: view.description,
            folder_parent_id: view.folder_parent_id,
            resource_type: view.resource_type,
            resource_type_id: view.resource_type_id,
            personal: view.personal,
            metadata_key_type: view.metadata_key_type,
            created: to_iso(view.created),
            modified: to_iso(view.modified),
            expired: to_iso(view.expired),
            password: view.password,
            totp,
            metadata_json: Value::Object(view.metadata).to_string(),
            secret_json: view.secret.map(|secret| Value::Object(secret).to_string()),
            error: view.error,
        }
    }
}

/// A resource to create. Its type comes from the fields set and the server's default version,
/// unless `resource_type` names it; fields the type does not have are refused.
#[derive(Default, uniffi::Record)]
pub struct NewResource {
    pub name: String,
    /// The type slug: `password-and-description`, `v5-default`, `v5-totp-standalone`…
    #[uniffi(default = None)]
    pub resource_type: Option<String>,
    #[uniffi(default = None)]
    pub username: Option<String>,
    /// v4 types have a single URI.
    #[uniffi(default = [])]
    pub uris: Vec<String>,
    #[uniffi(default = None)]
    pub description: Option<String>,
    /// The secret note of v5 types.
    #[uniffi(default = None)]
    pub note: Option<String>,
    #[uniffi(default = None)]
    pub password: Option<String>,
    #[uniffi(default = None)]
    pub totp: Option<TotpData>,
    #[uniffi(default = None)]
    pub pin_code: Option<String>,
    #[uniffi(default = None)]
    pub folder_parent_id: Option<String>,
    /// Expiry date, RFC 3339.
    #[uniffi(default = None)]
    pub expired: Option<String>,
    /// A JSON object of fields set as given, last: the v5 metadata or v4 resource fields.
    #[uniffi(default = None)]
    pub metadata_fields_json: Option<String>,
    /// A JSON object of secret fields set as given, last.
    #[uniffi(default = None)]
    pub secret_fields_json: Option<String>,
}

impl TryFrom<NewResource> for create::NewResource {
    type Error = PassboltError;

    fn try_from(resource: NewResource) -> Result<Self, PassboltError> {
        Ok(Self {
            resource_type: resource.resource_type,
            name: resource.name,
            username: resource.username,
            uris: resource.uris,
            description: resource.description,
            note: resource.note,
            password: resource.password,
            totp: resource.totp.map(types::TotpData::from),
            pin_code: resource.pin_code,
            folder_parent_id: resource.folder_parent_id,
            expired: resource.expired,
            metadata_fields: json_object(resource.metadata_fields_json, "metadata_fields_json")?,
            secret_fields: json_object(resource.secret_fields_json, "secret_fields_json")?,
            ..Self::default()
        })
    }
}

/// Changes to a resource; `None` keeps the current value.
#[derive(Default, uniffi::Record)]
pub struct ResourceChanges {
    #[uniffi(default = None)]
    pub name: Option<String>,
    #[uniffi(default = None)]
    pub username: Option<String>,
    /// v4 types have a single URI.
    #[uniffi(default = None)]
    pub uris: Option<Vec<String>>,
    #[uniffi(default = None)]
    pub description: Option<String>,
    /// The secret note of v5 types.
    #[uniffi(default = None)]
    pub note: Option<String>,
    #[uniffi(default = None)]
    pub password: Option<String>,
    #[uniffi(default = None)]
    pub pin_code: Option<String>,
    /// The TOTP fields to change. Adding a TOTP switches to the type with a TOTP.
    #[uniffi(default = None)]
    pub totp: Option<TotpData>,
    /// Switches to the type without TOTP.
    #[uniffi(default = false)]
    pub remove_totp: bool,
    /// The new expiry date, RFC 3339.
    #[uniffi(default = None)]
    pub expired: Option<String>,
    /// Clears the expiry.
    #[uniffi(default = false)]
    pub clear_expiry: bool,
    /// A JSON object of fields set as given, last: the v5 metadata or v4 resource fields.
    #[uniffi(default = None)]
    pub metadata_fields_json: Option<String>,
    /// A JSON object of secret fields set as given, last.
    #[uniffi(default = None)]
    pub secret_fields_json: Option<String>,
}

impl TryFrom<ResourceChanges> for update::ResourceChanges {
    type Error = PassboltError;

    fn try_from(changes: ResourceChanges) -> Result<Self, PassboltError> {
        if changes.clear_expiry && changes.expired.is_some() {
            return Err(PassboltError::InvalidArgument {
                reason: "expired and clear_expiry cannot be set together".into(),
            });
        }
        Ok(Self {
            name: changes.name,
            username: changes.username,
            uris: changes.uris,
            description: changes.description,
            note: changes.note,
            password: changes.password,
            pin_code: changes.pin_code,
            totp: changes.totp.map(types::TotpData::from),
            remove_totp: changes.remove_totp,
            expired: if changes.clear_expiry {
                Some(None)
            } else {
                changes.expired.map(Some)
            },
            metadata_fields: json_object(changes.metadata_fields_json, "metadata_fields_json")?,
            secret_fields: json_object(changes.secret_fields_json, "secret_fields_json")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::kept(None, false, "None")]
    #[case::set(
        Some("2030-01-01T00:00:00Z"),
        false,
        r#"Some(Some("2030-01-01T00:00:00Z"))"#
    )]
    #[case::cleared(None, true, "Some(None)")]
    fn test_changes_map_the_expiry(
        #[case] expired: Option<&str>,
        #[case] clear_expiry: bool,
        #[case] expected: &str,
    ) {
        let changes = ResourceChanges {
            expired: expired.map(String::from),
            clear_expiry,
            ..ResourceChanges::default()
        };

        let changes = update::ResourceChanges::try_from(changes).unwrap();

        assert_eq!(format!("{:?}", changes.expired), expected);
    }

    #[test]
    fn test_changes_refuse_an_expiry_both_set_and_cleared() {
        let changes = ResourceChanges {
            expired: Some("2030-01-01T00:00:00Z".into()),
            clear_expiry: true,
            ..ResourceChanges::default()
        };

        let error = update::ResourceChanges::try_from(changes).unwrap_err();

        assert!(
            matches!(error, PassboltError::InvalidArgument { .. }),
            "{error}"
        );
    }

    #[test]
    fn test_new_resource_refuses_fields_that_are_not_a_json_object() {
        let resource = NewResource {
            name: "GitHub".into(),
            metadata_fields_json: Some("[1, 2]".into()),
            ..NewResource::default()
        };

        let error = create::NewResource::try_from(resource).unwrap_err();

        assert!(
            matches!(error, PassboltError::InvalidArgument { .. }),
            "{error}"
        );
    }

    #[test]
    fn test_view_reads_the_totp_of_the_secret() {
        let resource: types::Resource =
            serde_json::from_value(serde_json::json!({"id": "r1", "name": "GitHub"})).unwrap();
        let secret = serde_json::json!({"password": "pw", "totp": {"secret_key": "JBSWY3DP"}});
        let view = view::ResourceView {
            id: "r1".into(),
            name: "GitHub".into(),
            username: String::new(),
            uri: String::new(),
            uris: Vec::new(),
            description: String::new(),
            folder_parent_id: None,
            resource_type: Some("v5-default-with-totp".into()),
            resource_type_id: None,
            personal: None,
            metadata_key_type: None,
            created: None,
            modified: None,
            expired: None,
            metadata: Map::new(),
            password: Some("pw".into()),
            secret: secret.as_object().cloned(),
            error: None,
            resource,
        };

        let view = ResourceView::from(view);

        assert_eq!(
            view.totp.and_then(|totp| totp.secret_key).as_deref(),
            Some("JBSWY3DP")
        );
        assert_eq!(
            view.secret_json.as_deref(),
            Some(secret.to_string().as_str())
        );
    }
}
