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

//! Upgrade v4 resources to v5 (administrators): their cleartext fields become encrypted metadata.

use std::collections::HashMap;

use serde_json::{json, Map, Value};

use crate::client::PassboltSdk;
use crate::error::{ApiError, PassboltError};
use crate::http::HttpClient;
use crate::resource::document;
use crate::types::{Resource, ResourceType, User};

/// The v5 type of each v4 type; secrets keep their shape.
const V4_TO_V5: [(&str, &str); 4] = [
    ("password-string", "v5-password-string"),
    ("password-and-description", "v5-default"),
    ("password-description-totp", "v5-default-with-totp"),
    ("totp", "v5-totp-standalone"),
];

/// Batches rejected because they changed meanwhile (404, 409) are fetched and upgraded again,
/// this many times over the whole run.
const MAX_REPLAYS: u32 = 3;

/// Upgrade the v4 resources the administrator can read to v5; returns how many were upgraded.
///
/// All of them or the shared ones only, batch by batch. A resource with a single user
/// permission gets metadata personal to that user when the settings allow it.
pub async fn upgrade_resources<H: HttpClient>(
    client: &PassboltSdk<H>,
    shared_only: bool,
) -> Result<usize, PassboltError> {
    let path = if shared_only {
        "/metadata/upgrade/resources.json?filter[is-shared]=1"
    } else {
        "/metadata/upgrade/resources.json?contain[permissions]=1"
    };
    let settings = client.metadata_settings().await?;
    if !settings.types.allows_resource_creation(true) {
        return Err(PassboltError::InvalidArgument(
            "The server does not allow v5 resources: enable their creation first".into(),
        ));
    }
    let personal_keys_allowed = settings.keys.allows_personal_keys();
    let resource_types = client.resource_types().await?;
    let mut owners: HashMap<String, User> = HashMap::new();

    let mut batch: Vec<Resource> = client.get(path).await?;
    let mut upgraded = 0;
    let mut replays = 0;
    while !batch.is_empty() {
        let mut changes = Vec::with_capacity(batch.len());
        for resource in &batch {
            let Some(v5_type) = v5_type_of(resource, &resource_types) else {
                continue;
            };
            let owner = match sole_owner(resource).filter(|_| personal_keys_allowed) {
                Some(owner_id) => {
                    if !owners.contains_key(owner_id) {
                        owners.insert(owner_id.to_string(), client.get_user(owner_id).await?);
                    }
                    owners.get(owner_id)
                }
                None => None,
            };
            changes.push(upgraded_resource(client, resource, v5_type, owner).await?);
        }
        if changes.is_empty() {
            return Err(PassboltError::Other(
                "The server lists resources that cannot be upgraded: stopped".into(),
            ));
        }
        let count = changes.len();
        match client
            .post::<Vec<Resource>>(path, &Value::Array(changes))
            .await
        {
            Ok(next) => {
                upgraded += count;
                batch = next;
            }
            Err(PassboltError::Api(ApiError {
                status: 404 | 409, ..
            })) if replays < MAX_REPLAYS => {
                replays += 1;
                batch = client.get(path).await?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(upgraded)
}

fn v5_type_of<'a>(
    resource: &Resource,
    resource_types: &'a [ResourceType],
) -> Option<&'a ResourceType> {
    let v4_slug = resource_types
        .iter()
        .find(|resource_type| {
            resource.resource_type_id.as_deref() == Some(resource_type.id.as_str())
        })?
        .slug
        .as_str();
    let v5_slug = V4_TO_V5.iter().find(|(v4, _)| *v4 == v4_slug)?.1;
    resource_types
        .iter()
        .find(|resource_type| resource_type.slug == v5_slug)
}

/// The user who alone has a permission on it.
fn sole_owner(resource: &Resource) -> Option<&str> {
    match resource.permissions.as_slice() {
        [permission] if permission.aro.as_deref() == Some("User") => {
            permission.aro_foreign_key.as_deref()
        }
        _ => None,
    }
}

/// The upgrade of one resource: its fields encrypted as v5 metadata, for its sole `owner`
/// when given, for the shared metadata key otherwise.
async fn upgraded_resource<H: HttpClient>(
    client: &PassboltSdk<H>,
    resource: &Resource,
    v5_type: &ResourceType,
    owner: Option<&User>,
) -> Result<Value, PassboltError> {
    let mut fields = Map::new();
    fields.insert("name".into(), resource.name.clone().into());
    if let Some(username) = &resource.username {
        fields.insert("username".into(), username.clone().into());
    }
    if let Some(uri) = resource.uri.as_ref().filter(|uri| !uri.is_empty()) {
        fields.insert("uris".into(), json!([uri]));
    }
    if let Some(description) = &resource.description {
        fields.insert("description".into(), description.clone().into());
    }
    let metadata = document::metadata(v5_type, &fields)?;
    let encrypted = match owner {
        Some(owner) => document::encrypt_metadata(client, &metadata, true, owner).await?,
        None => client.encrypt_shared_metadata(&metadata).await?,
    };
    Ok(json!({
        "id": resource.id,
        "metadata": encrypted.metadata,
        "metadata_key_id": encrypted.metadata_key_id,
        "metadata_key_type": encrypted.metadata_key_type,
        "modified": resource.modified.map(|modified| modified.to_rfc3339()),
        "modified_by": resource.modified_by,
    }))
}
