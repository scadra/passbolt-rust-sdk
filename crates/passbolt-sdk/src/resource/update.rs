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

use serde_json::{json, Map, Value};

use crate::client::{PassboltSdk, UserQuery};
use crate::crypto;
use crate::error::PassboltError;
use crate::http::HttpClient;
use crate::resource::document::{self, invalid, SECRET_OBJECT_TYPE};
use crate::resource::view::v4_fields;
use crate::types::{Resource, ResourceType, SecretPayload, TotpData, UpdateResourcePayload};

/// Changes to a resource; `None` keeps the current value.
///
/// Bindings read it from JSON with these field names; `"expired": null` clears the expiry.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResourceChanges {
    pub name: Option<String>,
    pub username: Option<String>,
    /// v4 types have a single URI.
    pub uris: Option<Vec<String>>,
    /// Stored in the v5 metadata, or in the v4 secret.
    pub description: Option<String>,
    /// Secret note: the secret description of v5 types.
    pub note: Option<String>,
    pub password: Option<String>,
    pub pin_code: Option<String>,
    /// The TOTP fields to change. Adding a TOTP switches to the type with a TOTP.
    pub totp: Option<TotpData>,
    /// Switches to the type without TOTP.
    pub remove_totp: bool,
    /// `Some(None)` clears the expiry.
    #[serde(deserialize_with = "present")]
    pub expired: Option<Option<String>>,
    /// Fields set as given, last: the v5 metadata or v4 resource fields (`--field`).
    pub metadata_fields: Map<String, Value>,
    /// Secret fields set as given, last (`--secret-field`).
    pub secret_fields: Map<String, Value>,
}

/// A field present in the JSON, even `null`: `Some(None)` then.
#[allow(clippy::option_option)] // absent, `null` and a date are three different changes
fn present<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Option<String>>, D::Error> {
    serde::Deserialize::deserialize(deserializer).map(Some)
}

impl ResourceChanges {
    fn changes_the_secret(&self) -> bool {
        self.note.is_some()
            || self.password.is_some()
            || self.pin_code.is_some()
            || self.totp.is_some()
            || self.remove_totp
            || !self.secret_fields.is_empty()
    }
}

/// Update a resource, keeping its type and every field it does not change.
///
/// v5 metadata is decrypted, changed and encrypted again for the same kind of key. A changed
/// secret is encrypted for every user with access, group members included.
pub async fn update_resource<H: HttpClient>(
    client: &PassboltSdk<H>,
    id: &str,
    changes: &ResourceChanges,
) -> Result<Resource, PassboltError> {
    let resource = client.get_resource(id).await?;
    let resource_types = client.resource_types().await?;
    let find_type = |slug_or_id: &str| {
        resource_types
            .iter()
            .find(|resource_type| {
                resource_type.id == slug_or_id || resource_type.slug == slug_or_id
            })
            .ok_or_else(|| {
                PassboltError::InvalidArgument(format!("Unknown resource type: {slug_or_id}"))
            })
    };
    let current_type = find_type(resource.resource_type_id.as_deref().unwrap_or_default())?;
    let new_type = find_type(next_slug(current_type, changes)?)?;

    let (mut fields, kept_fields) = current_fields(client, &resource, current_type).await?;
    // Leaving `password-string`, the clear description moves to the secret, as the browser
    // extension does: the new type keeps it there.
    let leaves_clear_description = current_type.resource_has_field("description")
        && !new_type.resource_has_field("description");
    let moved_description = if leaves_clear_description {
        fields.remove("description")
    } else {
        None
    };
    apply_field_changes(&mut fields, changes, new_type)?;

    let description_in_secret =
        changes.description.is_some() && !new_type.resource_has_field("description");
    let secret = if changes.changes_the_secret()
        || description_in_secret
        || new_type.id != current_type.id
    {
        let current = client
            .decrypt_resource_secret_text(&resource)
            .await?
            .unwrap_or_default();
        let (secret, kept_secret_fields) = changed_secret(
            &current,
            current_type,
            new_type,
            changes,
            moved_description.clone(),
        )?;
        document::validate(
            new_type,
            &fields,
            &secret,
            &[kept_fields.clone(), kept_secret_fields].concat(),
        )?;
        Some(secret)
    } else {
        document::validate_resource(new_type, &fields, &kept_fields)?;
        None
    };

    let mut payload = UpdateResourcePayload {
        name: None,
        username: None,
        uri: None,
        description: None,
        resource_type_id: Some(new_type.id.clone()),
        secrets: None,
        expired: changes
            .expired
            .clone()
            .map(|expired| expired.map_or(Value::Null, Value::from)),
        metadata: None,
        metadata_key_id: None,
        metadata_key_type: None,
    };
    if let Some(secret) = secret {
        payload.secrets = Some(encrypt_for_users_with_access(client, id, &secret).await?);
    }
    if new_type.is_v5() {
        let metadata = document::metadata(new_type, &fields)?;
        // As the browser extension decides it: personal while only the user has access and
        // the settings allow personal keys.
        let personal = resource.personal == Some(true)
            && client
                .metadata_settings()
                .await?
                .keys
                .allows_personal_keys();
        let me = client.get_me().await?;
        let encrypted = document::encrypt_metadata(client, &metadata, personal, &me).await?;
        payload.metadata = Some(encrypted.metadata);
        payload.metadata_key_id = Some(encrypted.metadata_key_id);
        payload.metadata_key_type = Some(encrypted.metadata_key_type.into());
    } else {
        let field = |name: &str| fields.get(name).and_then(Value::as_str).map(String::from);
        payload.name = field("name");
        payload.username = field("username");
        // `null` empties a URI the changes removed.
        payload.uri = match field("uri") {
            Some(uri) => Some(uri.into()),
            None if changes.uris.is_some() => Some(Value::Null),
            None => None,
        };
        // `null` empties the clear description that moved to the secret.
        payload.description = match moved_description {
            Some(_) => Some(Value::Null),
            None => field("description").map(Value::from),
        };
    }

    client.update_resource(id, &payload).await
}

/// The type after the TOTP changes: adding or removing a TOTP switches to the matching type.
fn next_slug<'a>(
    current_type: &'a ResourceType,
    changes: &ResourceChanges,
) -> Result<&'a str, PassboltError> {
    let has_totp = current_type.secret_has_field("totp");
    let slug = current_type.slug.as_str();
    if changes.remove_totp {
        return match slug {
            "password-description-totp" => Ok("password-and-description"),
            "v5-default-with-totp" => Ok("v5-default"),
            "totp" | "v5-totp-standalone" => Err(invalid(
                current_type,
                "the TOTP is all it keeps secret: delete the resource instead",
            )),
            _ => Err(invalid(current_type, "this resource has no TOTP")),
        };
    }
    let Some(totp) = &changes.totp else {
        return Ok(slug);
    };
    if has_totp {
        return Ok(slug);
    }
    if totp.secret_key.is_none() {
        return Err(invalid(
            current_type,
            "this resource has no TOTP: give its key",
        ));
    }
    match slug {
        "password-string" | "password-and-description" => Ok("password-description-totp"),
        "v5-default" | "v5-password-string" => Ok("v5-default-with-totp"),
        _ => Err(invalid(
            current_type,
            "a TOTP cannot be added to this resource type",
        )),
    }
}

/// The current v4 fields or decrypted v5 metadata, without the v5 envelope, and their
/// field names unknown to the SDK's schema of the type, kept as they are.
async fn current_fields<H: HttpClient>(
    client: &PassboltSdk<H>,
    resource: &Resource,
    current_type: &ResourceType,
) -> Result<(Map<String, Value>, Vec<String>), PassboltError> {
    let mut fields = if current_type.is_v5() {
        let metadata = client
            .decrypt_resource_metadata(resource)
            .await?
            .ok_or_else(|| invalid(current_type, "the resource has no metadata"))?;
        match serde_json::to_value(metadata)? {
            Value::Object(fields) => fields,
            _ => Map::new(),
        }
    } else {
        v4_fields(resource)
    };
    fields.remove("object_type");
    fields.remove("resource_type_id");
    fields.retain(|_, value| !value.is_null());
    let kept_fields = fields.keys().cloned().collect();
    Ok((fields, kept_fields))
}

fn apply_field_changes(
    fields: &mut Map<String, Value>,
    changes: &ResourceChanges,
    new_type: &ResourceType,
) -> Result<(), PassboltError> {
    if let Some(name) = &changes.name {
        fields.insert("name".into(), name.clone().into());
    }
    if let Some(username) = &changes.username {
        fields.insert("username".into(), username.clone().into());
    }
    if let Some(uris) = &changes.uris {
        if new_type.is_v5() {
            fields.insert("uris".into(), json!(uris));
        } else {
            match uris.as_slice() {
                [] => {
                    fields.remove("uri");
                }
                [uri] => {
                    fields.insert("uri".into(), uri.clone().into());
                }
                _ => return Err(invalid(new_type, "v4 resource types have a single URI")),
            }
        }
    }
    if let Some(description) = &changes.description {
        if new_type.resource_has_field("description") {
            fields.insert("description".into(), description.clone().into());
        }
    }
    fields.extend(changes.metadata_fields.clone());
    Ok(())
}

/// The secret with the changes applied, in the shape of `new_type`, and the field names
/// it already had that the schema does not declare.
fn changed_secret(
    current: &str,
    current_type: &ResourceType,
    new_type: &ResourceType,
    changes: &ResourceChanges,
    moved_description: Option<Value>,
) -> Result<(Value, Vec<String>), PassboltError> {
    let mut secret = if current_type.secret_is_string() {
        let mut secret = Map::new();
        secret.insert("password".into(), current.into());
        secret
    } else {
        match serde_json::from_str(current) {
            Ok(Value::Object(secret)) => secret,
            _ => {
                return Err(invalid(
                    current_type,
                    "the current secret is not a JSON object",
                ))
            }
        }
    };
    let kept_fields = secret.keys().cloned().collect();

    if let Some(description) = moved_description {
        secret.insert("description".into(), description);
    }
    if let Some(password) = &changes.password {
        secret.insert("password".into(), password.clone().into());
    }
    if let Some(pin_code) = &changes.pin_code {
        secret.insert("pin_code".into(), pin_code.clone().into());
    }
    if let Some(description) = &changes.description {
        if !new_type.resource_has_field("description") {
            secret.insert("description".into(), description.clone().into());
        }
    }
    if let Some(note) = &changes.note {
        if !new_type.is_v5() {
            return Err(invalid(
                new_type,
                "a note is the secret description of v5 types",
            ));
        }
        secret.insert("description".into(), note.clone().into());
    }
    if changes.remove_totp {
        secret.remove("totp");
    } else if let Some(totp) = &changes.totp {
        let merged = merged_totp(secret.get("totp"), totp)?;
        secret.insert("totp".into(), merged);
    }
    secret.extend(changes.secret_fields.clone());
    // Written by older clients, not part of any resource type.
    if let Some(Value::Object(totp)) = secret.get_mut("totp") {
        totp.remove("issuer");
    }

    if new_type.secret_is_string() {
        let password = secret.remove("password").unwrap_or_default();
        if let Some(field) = secret.keys().next() {
            return Err(invalid(
                new_type,
                &format!("{field} is not allowed by this resource type"),
            ));
        }
        return Ok((password, Vec::new()));
    }
    if new_type.is_v5() {
        secret.insert("object_type".into(), SECRET_OBJECT_TYPE.into());
    }
    Ok((Value::Object(secret), kept_fields))
}

/// The current TOTP with the given fields replaced; a new TOTP starts from SHA1, 6 digits, 30 s.
fn merged_totp(current: Option<&Value>, changes: &TotpData) -> Result<Value, PassboltError> {
    let mut totp = match current {
        Some(Value::Object(totp)) => totp.clone(),
        _ => match json!({"algorithm": "SHA1", "digits": 6, "period": 30}) {
            Value::Object(defaults) => defaults,
            _ => Map::new(),
        },
    };
    if let Value::Object(changed) = serde_json::to_value(changes)? {
        totp.extend(changed);
    }
    Ok(Value::Object(totp))
}

/// The secret encrypted for each user with access to the resource, signed by the user.
async fn encrypt_for_users_with_access<H: HttpClient>(
    client: &PassboltSdk<H>,
    resource_id: &str,
    secret: &Value,
) -> Result<Vec<SecretPayload>, PassboltError> {
    let plaintext = document::secret_plaintext(secret)?;
    let users = client
        .get_users(UserQuery {
            resource_ids: vec![resource_id.to_string()],
            ..UserQuery::default()
        })
        .await?;
    users
        .iter()
        .map(|user| {
            let (public_key, _) = document::public_key_of(client.openpgp(), user)?;
            Ok(SecretPayload {
                user_id: user.id.clone(),
                data: crypto::sign_and_encrypt(
                    &plaintext,
                    &[client.user_signer()],
                    &[&public_key],
                )?,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_changes_from_json_tell_a_null_expiry_from_an_absent_one() {
        let clearing: ResourceChanges = serde_json::from_str(r#"{"expired": null}"#).unwrap();
        let keeping: ResourceChanges = serde_json::from_str(r#"{"name": "GitLab"}"#).unwrap();

        assert_eq!(clearing.expired, Some(None));
        assert_eq!(keeping.expired, None);
        assert_eq!(keeping.name.as_deref(), Some("GitLab"));
    }

    #[test]
    fn test_changes_from_json_refuse_an_unknown_field() {
        assert!(serde_json::from_str::<ResourceChanges>(r#"{"nmae": "typo"}"#).is_err());
    }
}
