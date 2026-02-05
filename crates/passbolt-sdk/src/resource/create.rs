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

use crate::client::PassboltSdk;
use crate::crypto;
use crate::error::PassboltError;
use crate::http::HttpClient;
use crate::resource::document::{self, invalid, SECRET_OBJECT_TYPE};
use crate::resource::share;
use crate::types::{
    CreateResourcePayload, CustomField, Resource, ResourceType, SecretPayload, TotpData,
};

/// A resource to create. Fields the resource type does not have are refused.
///
/// Bindings read it from JSON with these field names; absent fields are empty.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NewResource {
    /// Resource type slug. By default: from the fields set and the server's default version.
    pub resource_type: Option<String>,
    pub name: String,
    pub username: Option<String>,
    /// v4 types have a single URI.
    pub uris: Vec<String>,
    /// Stored in the v5 metadata, or in the v4 secret.
    pub description: Option<String>,
    /// Secret note, the content of a `v5-note`.
    pub note: Option<String>,
    pub password: Option<String>,
    pub totp: Option<TotpData>,
    pub pin_code: Option<String>,
    /// `{type, value, background_color}`.
    pub icon: Option<Value>,
    /// Each field with its metadata side (`metadata_key`…) and secret side (`secret_value`…).
    pub custom_fields: Vec<CustomField>,
    pub folder_parent_id: Option<String>,
    /// Expiry date, RFC 3339.
    pub expired: Option<String>,
    /// Fields set as given, last: the v5 metadata or v4 resource fields (`--field`).
    pub metadata_fields: Map<String, Value>,
    /// Secret fields set as given, last (`--secret-field`).
    pub secret_fields: Map<String, Value>,
}

/// Create a resource, encrypting its secret for the user, and v5 metadata as the server settings
/// require. Created in a folder, it then gets the folder's permissions, as the browser extension
/// gives them.
pub async fn create_resource<H: HttpClient>(
    client: &PassboltSdk<H>,
    new_resource: &NewResource,
) -> Result<Resource, PassboltError> {
    let settings = client.metadata_settings().await?;
    let slug = match &new_resource.resource_type {
        Some(slug) => slug.as_str(),
        None => default_slug(
            new_resource,
            settings.types.creates_v5_resources_by_default(),
        )?,
    };
    if slug == "v5-password-string" {
        return Err(PassboltError::InvalidArgument(
            "v5-password-string is read-only: the server refuses to create it".into(),
        ));
    }
    let resource_type = client.resource_type_by_slug(slug).await?;
    if !settings
        .types
        .allows_resource_creation(resource_type.is_v5())
    {
        let version = if resource_type.is_v5() { "v5" } else { "v4" };
        return Err(PassboltError::InvalidArgument(format!(
            "The server settings do not allow creating {version} resources"
        )));
    }

    let documents = Documents::build(new_resource, &resource_type)?;
    let me = client.get_me().await?;
    let (user_public_key, _) = document::public_key_of(&me)?;
    let secret = crypto::sign_and_encrypt(
        &document::secret_plaintext(&documents.secret)?,
        &[client.user_signer()],
        &[&user_public_key],
    )?;

    let mut payload = CreateResourcePayload {
        name: None,
        username: None,
        uri: None,
        description: None,
        folder_parent_id: new_resource.folder_parent_id.clone(),
        resource_type_id: Some(resource_type.id.clone()),
        secrets: vec![SecretPayload {
            user_id: me.id.clone(),
            data: secret,
        }],
        expired: new_resource.expired.clone(),
        metadata: None,
        metadata_key_id: None,
        metadata_key_type: None,
    };
    if resource_type.is_v5() {
        let resource_metadata = document::metadata(&resource_type, &documents.resource)?;
        let personal = settings.keys.allows_personal_keys();
        let encrypted =
            document::encrypt_metadata(client, &resource_metadata, personal, &me).await?;
        payload.metadata = Some(encrypted.metadata);
        payload.metadata_key_id = Some(encrypted.metadata_key_id);
        payload.metadata_key_type = Some(encrypted.metadata_key_type.into());
    } else {
        let field = |name: &str| {
            documents
                .resource
                .get(name)
                .and_then(Value::as_str)
                .map(String::from)
        };
        payload.name = field("name");
        payload.username = field("username");
        payload.uri = field("uri");
        payload.description = field("description");
    }

    let created = client.create_resource(&payload).await?;
    if let Some(folder_id) = new_resource
        .folder_parent_id
        .as_deref()
        .filter(|folder_id| !folder_id.is_empty())
    {
        share::inherit_folder_permissions(client, &created.id, folder_id).await?;
    }
    Ok(created)
}

/// Whether resources of type `slug` need a password.
#[must_use]
pub fn requires_password(slug: &str) -> bool {
    matches!(
        slug,
        "password-string"
            | "password-and-description"
            | "password-description-totp"
            | "v5-default"
            | "v5-default-with-totp"
    )
}

/// The slug matching the fields set, `--secret-field` ones included, in the server's default
/// version.
fn default_slug(new_resource: &NewResource, v5: bool) -> Result<&'static str, PassboltError> {
    let secret_field = |name: &str| new_resource.secret_fields.contains_key(name);
    let has_password = new_resource.password.is_some() || secret_field("password");
    let has_totp = new_resource.totp.is_some() || secret_field("totp");
    let has_pin_code = new_resource.pin_code.is_some() || secret_field("pin_code");
    let has_custom_fields = !new_resource.custom_fields.is_empty() || secret_field("custom_fields");
    let has_note = new_resource.note.is_some() || secret_field("description");
    let slug = match (v5, has_password, has_totp) {
        (true, true, true) => "v5-default-with-totp",
        (true, true, false) => "v5-default",
        (true, false, true) => "v5-totp-standalone",
        (true, false, false) if has_pin_code => "v5-pin-code",
        (true, false, false) if has_custom_fields => "v5-custom-fields",
        (true, false, false) if has_note => "v5-note",
        (false, true, true) => "password-description-totp",
        (false, true, false) => "password-and-description",
        (false, false, true) => "totp",
        _ => return Err(PassboltError::InvalidArgument(
            "Nothing to keep secret: set a password, a TOTP, a PIN code, custom fields or a note"
                .into(),
        )),
    };
    Ok(slug)
}

/// The `resource` (v4 fields or v5 metadata) and `secret` documents, checked against the type.
struct Documents {
    resource: Map<String, Value>,
    secret: Value,
}

impl Documents {
    fn build(
        new_resource: &NewResource,
        resource_type: &ResourceType,
    ) -> Result<Self, PassboltError> {
        let invalid = |reason: String| invalid(resource_type, &reason);
        let mut resource = Map::new();
        let mut secret = Map::new();
        resource.insert("name".into(), new_resource.name.clone().into());
        insert(
            &mut resource,
            "username",
            new_resource.username.clone().map(Value::from),
        );
        if resource_type.is_v5() {
            if !new_resource.uris.is_empty() {
                resource.insert("uris".into(), json!(new_resource.uris));
            }
        } else if let [uri] = new_resource.uris.as_slice() {
            resource.insert("uri".into(), uri.clone().into());
        } else if new_resource.uris.len() > 1 {
            return Err(invalid("v4 resource types have a single URI".into()));
        }
        let description = new_resource.description.clone().map(Value::from);
        if resource_type.resource_has_field("description") {
            insert(&mut resource, "description", description);
        } else {
            insert(&mut secret, "description", description);
        }
        if let Some(note) = &new_resource.note {
            if secret.contains_key("description") || !resource_type.is_v5() {
                return Err(invalid(
                    "a note is the secret description of v5 types".into(),
                ));
            }
            secret.insert("description".into(), note.clone().into());
        }
        insert(&mut resource, "icon", new_resource.icon.clone());
        if !new_resource.custom_fields.is_empty() {
            let (metadata_side, secret_side) = split_custom_fields(&new_resource.custom_fields);
            resource.insert("custom_fields".into(), serde_json::to_value(metadata_side)?);
            secret.insert("custom_fields".into(), serde_json::to_value(secret_side)?);
        }
        insert(
            &mut secret,
            "password",
            new_resource.password.clone().map(Value::from),
        );
        insert(
            &mut secret,
            "totp",
            new_resource
                .totp
                .as_ref()
                .map(serde_json::to_value)
                .transpose()?,
        );
        insert(
            &mut secret,
            "pin_code",
            new_resource.pin_code.clone().map(Value::from),
        );
        resource.extend(new_resource.metadata_fields.clone());
        secret.extend(new_resource.secret_fields.clone());

        let secret = if resource_type.secret_is_string() {
            let password = secret.remove("password").unwrap_or(Value::Null);
            if let Some(field) = secret.keys().next() {
                return Err(invalid(format!(
                    "{field} is not allowed by this resource type"
                )));
            }
            password
        } else {
            if resource_type.is_v5() {
                secret.insert("object_type".into(), SECRET_OBJECT_TYPE.into());
            }
            Value::Object(secret)
        };

        document::validate(resource_type, &resource, &secret, &[])?;
        Ok(Self { resource, secret })
    }
}

fn insert(document: &mut Map<String, Value>, key: &str, value: Option<Value>) {
    if let Some(value) = value {
        document.insert(key.into(), value);
    }
}

/// The metadata side and the secret side of custom fields, paired by id.
fn split_custom_fields(custom_fields: &[CustomField]) -> (Vec<CustomField>, Vec<CustomField>) {
    custom_fields
        .iter()
        .map(|field| {
            let side = || CustomField {
                id: field.id.clone(),
                field_type: field.field_type.clone(),
                metadata_key: None,
                metadata_value: None,
                secret_key: None,
                secret_value: None,
            };
            let metadata_side = CustomField {
                metadata_key: field.metadata_key.clone(),
                metadata_value: field.metadata_value.clone(),
                ..side()
            };
            let secret_side = CustomField {
                secret_key: field.secret_key.clone(),
                secret_value: field.secret_value.clone(),
                ..side()
            };
            (metadata_side, secret_side)
        })
        .unzip()
}
