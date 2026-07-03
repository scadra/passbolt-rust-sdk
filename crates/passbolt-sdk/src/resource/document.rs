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

//! What create and update share: the `resource` and `secret` documents of a resource type,
//! their validation, and their encryption.

use serde_json::{Map, Value};

use crate::client::PassboltSdk;
use crate::crypto::{OpenPgp, PublicKey};
use crate::error::PassboltError;
use crate::http::HttpClient;
use crate::metadata::{self, EncryptedMetadata};
use crate::resource::schema;
use crate::types::{ResourceMetadata, ResourceType, User};

pub const METADATA_OBJECT_TYPE: &str = "PASSBOLT_RESOURCE_METADATA";
pub const SECRET_OBJECT_TYPE: &str = "PASSBOLT_SECRET_DATA";

pub fn invalid(resource_type: &ResourceType, reason: &str) -> PassboltError {
    PassboltError::InvalidArgument(format!("{}: {reason}", resource_type.slug))
}

/// Check the documents against the schemas of `resource_type`.
///
/// Top-level fields listed in `kept_fields` are not checked: an update keeps the fields
/// a newer client wrote, this SDK cannot tell whether they are valid.
pub fn validate(
    resource_type: &ResourceType,
    resource: &Map<String, Value>,
    secret: &Value,
    kept_fields: &[String],
) -> Result<(), PassboltError> {
    validate_resource(resource_type, resource, kept_fields)?;
    let schema = schema_of(resource_type, ResourceType::secret_schema)?;
    let secret = match secret {
        Value::Object(fields) => without_kept(fields, schema, kept_fields),
        secret => secret.clone(),
    };
    schema::validate(schema, &secret).map_err(|reason| invalid(resource_type, &reason))
}

/// Check the v4 fields or v5 metadata only, when the secret does not change.
pub fn validate_resource(
    resource_type: &ResourceType,
    resource: &Map<String, Value>,
    kept_fields: &[String],
) -> Result<(), PassboltError> {
    let schema = schema_of(resource_type, ResourceType::resource_schema)?;
    schema::validate(schema, &without_kept(resource, schema, kept_fields))
        .map_err(|reason| invalid(resource_type, &reason))
}

fn schema_of(
    resource_type: &ResourceType,
    schema: fn(&ResourceType) -> Option<&'static Value>,
) -> Result<&'static Value, PassboltError> {
    schema(resource_type)
        .ok_or_else(|| invalid(resource_type, "this resource type is not supported"))
}

/// `document` without the kept fields its schema does not declare.
fn without_kept(document: &Map<String, Value>, schema: &Value, kept_fields: &[String]) -> Value {
    let declared = schema.get("properties").and_then(Value::as_object);
    let mut checked = document.clone();
    checked.retain(|key, _| {
        !kept_fields.contains(key) || declared.is_some_and(|declared| declared.contains_key(key))
    });
    Value::Object(checked)
}

/// The metadata to encrypt: `resource` with the v5 envelope.
pub fn metadata(
    resource_type: &ResourceType,
    resource: &Map<String, Value>,
) -> Result<ResourceMetadata, PassboltError> {
    let mut metadata = resource.clone();
    metadata.insert("object_type".into(), METADATA_OBJECT_TYPE.into());
    metadata.insert("resource_type_id".into(), resource_type.id.clone().into());
    Ok(serde_json::from_value(Value::Object(metadata))?)
}

/// What is encrypted: the password itself for `password-string` types, JSON otherwise.
pub fn secret_plaintext(secret: &Value) -> Result<String, PassboltError> {
    Ok(match secret {
        Value::String(password) => password.clone(),
        secret => serde_json::to_string(secret)?,
    })
}

/// The user's public key as the server knows it, with its id there.
pub fn public_key_of<'a>(
    openpgp: &OpenPgp,
    user: &'a User,
) -> Result<(PublicKey, &'a str), PassboltError> {
    let gpgkey = user.gpg_key.as_ref();
    let armored_key = gpgkey
        .and_then(|gpgkey| gpgkey.armored_key.as_deref())
        .ok_or_else(|| PassboltError::NotFound(format!("GPG key of user {}", user.id)))?;
    let gpgkey_id = gpgkey
        .and_then(|gpgkey| gpgkey.id.as_deref())
        .unwrap_or_default();
    Ok((openpgp.parse_public_key(armored_key)?, gpgkey_id))
}

/// Encrypt metadata for the user (`personal`) or for the active shared metadata key.
pub async fn encrypt_metadata<H: HttpClient>(
    client: &PassboltSdk<H>,
    metadata: &ResourceMetadata,
    personal: bool,
    me: &User,
) -> Result<EncryptedMetadata, PassboltError> {
    let user = client.user_signer();
    if personal {
        let (public_key, gpgkey_id) = public_key_of(client.openpgp(), me)?;
        metadata::encrypt_for_user(metadata, &user, &public_key, gpgkey_id).await
    } else {
        client.encrypt_shared_metadata(metadata).await
    }
}
