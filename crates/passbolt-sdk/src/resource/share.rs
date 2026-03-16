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

use crate::client::PassboltSdk;
use crate::crypto;
use crate::error::PassboltError;
use crate::http::HttpClient;
use crate::permission::{changes, grants, moved, OWNER};
use crate::resource::document;
use crate::types::{
    build_revoke_changes, Permission, Resource, ResourceType, SecretPayload, ShareChange,
    SharePayload, UpdateResourcePayload,
};

/// Share a resource with users and groups, or revoke their access (`permission_type == -1`).
///
/// Existing permissions are updated, not duplicated. Users who gain access, group members
/// included, get the secret as it is. Personal v5 metadata moves to the shared key first:
/// the server refuses to share it.
pub async fn share_resource<H: HttpClient>(
    client: &PassboltSdk<H>,
    id: &str,
    user_ids: &[String],
    group_ids: &[String],
    permission_type: i32,
) -> Result<(), PassboltError> {
    let existing = client.get_resource_permissions(id).await?;
    let permissions = requested_changes(&existing, user_ids, group_ids, permission_type)?;
    if permissions.is_empty() {
        return Ok(());
    }
    if permission_type == -1 {
        let payload = SharePayload {
            permissions,
            secrets: None,
        };
        client.share_resource(id, &payload).await?;
        return Ok(());
    }
    apply_changes(client, id, permissions).await
}

/// The changes asked by `share`, refused as go-passbolt refuses them: the same user or group
/// twice, a permission it already has, a revocation of a permission it does not have.
pub(crate) fn requested_changes(
    existing: &[Permission],
    user_ids: &[String],
    group_ids: &[String],
    permission_type: i32,
) -> Result<Vec<ShareChange>, PassboltError> {
    let requested: Vec<(&str, &str)> = aros(user_ids, group_ids).collect();
    for (index, aro) in requested.iter().enumerate() {
        if let Some(other) = requested[index + 1..].iter().position(|other| other == aro) {
            return Err(PassboltError::InvalidArgument(format!(
                "change {index} and {} are Both About the same ARO {} ID: {}, there can only be \
                 once change per ARO",
                index + 1 + other,
                aro.0,
                aro.1
            )));
        }
    }
    let current = |(aro, aro_foreign_key): (&str, &str)| {
        existing.iter().find(|permission| {
            permission.aro.as_deref() == Some(aro)
                && permission.aro_foreign_key.as_deref() == Some(aro_foreign_key)
        })
    };
    for &(aro, aro_foreign_key) in &requested {
        match current((aro, aro_foreign_key)) {
            None if permission_type == -1 => {
                return Err(PassboltError::InvalidArgument(format!(
                    "permission for {aro} {aro_foreign_key} Cannot be Deleted as No Matching \
                     Permission Exists"
                )))
            }
            Some(permission) if permission.permission_type == Some(permission_type) => {
                return Err(PassboltError::InvalidArgument(format!(
                    "permission for {aro} {aro_foreign_key} is already Type {permission_type}"
                )))
            }
            _ => {}
        }
    }
    if permission_type == -1 {
        return Ok(build_revoke_changes(existing, user_ids, group_ids));
    }
    Ok(merge_changes(
        existing,
        requested.into_iter(),
        permission_type,
    ))
}

/// `(aro, id)` of the users then the groups.
pub(crate) fn aros<'a>(
    user_ids: &'a [String],
    group_ids: &'a [String],
) -> impl Iterator<Item = (&'a str, &'a str)> {
    user_ids
        .iter()
        .map(|user_id| ("User", user_id.as_str()))
        .chain(
            group_ids
                .iter()
                .map(|group_id| ("Group", group_id.as_str())),
        )
}

/// Move a resource into `destination` (`None`: the root) with the permissions a move gives.
///
/// As the browser extension does: those it did not get from the folder it leaves, plus the
/// destination's, the higher level winning (see [`moved`]). Only an owner can; the permissions
/// are checked before the move, applied after it.
pub async fn move_with_folder_permissions<H: HttpClient>(
    client: &PassboltSdk<H>,
    id: &str,
    destination: Option<&str>,
) -> Result<(), PassboltError> {
    let resource = client.get_resource(id).await?;
    if !is_owner(resource.permission.as_ref()) {
        return Err(PassboltError::InvalidArgument(format!(
            "Only an owner of resource {id} can give it the folder permissions"
        )));
    }
    let current = client.get_resource_permissions(id).await?;
    let parent = match resource.folder_parent_id.as_deref() {
        Some(parent_id) => Some(client.get_folder_permissions(parent_id).await?),
        None => None,
    };
    let destination_permissions = match destination {
        Some(folder_id) => Some(client.get_folder_permissions(folder_id).await?),
        None => None,
    };
    let target = moved(
        &current,
        parent.as_deref(),
        destination_permissions.as_deref(),
        resource.permission.as_ref(),
    )?;
    client.move_resource(id, destination).await?;
    let changes = changes(&current, &target);
    if changes.is_empty() {
        return Ok(());
    }
    apply_changes(client, id, changes).await
}

/// Give the resource just created in `folder_id` exactly the folder's permissions, as the
/// browser extension does.
pub(crate) async fn inherit_folder_permissions<H: HttpClient>(
    client: &PassboltSdk<H>,
    id: &str,
    folder_id: &str,
) -> Result<(), PassboltError> {
    let folder_permissions = client.get_folder_permissions(folder_id).await?;
    let current = client.get_resource_permissions(id).await?;
    let changes = changes(&current, &grants(&folder_permissions));
    if changes.is_empty() {
        return Ok(());
    }
    apply_changes(client, id, changes).await
}

pub(crate) fn is_owner(permission: Option<&Permission>) -> bool {
    permission.and_then(|permission| permission.permission_type) == Some(OWNER)
}

/// Simulate `permissions`, give the users who gain access the secret, then share.
pub(crate) async fn apply_changes<H: HttpClient>(
    client: &PassboltSdk<H>,
    id: &str,
    permissions: Vec<ShareChange>,
) -> Result<(), PassboltError> {
    let resource = client.get_resource(id).await?;
    if resource.is_v5() && resource.metadata_key_type.as_deref() == Some("user_key") {
        move_metadata_to_the_shared_key(client, &resource).await?;
    }
    let added_user_ids = client.simulate_share_resource(id, &permissions).await?;
    let secrets = if added_user_ids.is_empty() {
        None
    } else {
        Some(secrets_for(client, &resource, &added_user_ids).await?)
    };
    client
        .share_resource(
            id,
            &SharePayload {
                permissions,
                secrets,
            },
        )
        .await
}

/// A change per `(aro, id)`: an update of its existing permission, or a new one.
pub(crate) fn merge_changes<'a>(
    existing: &[Permission],
    aros: impl Iterator<Item = (&'a str, &'a str)>,
    permission_type: i32,
) -> Vec<ShareChange> {
    aros.filter_map(|(aro, aro_foreign_key)| {
        let current = existing.iter().find(|permission| {
            permission.aro.as_deref() == Some(aro)
                && permission.aro_foreign_key.as_deref() == Some(aro_foreign_key)
        });
        if current.is_some_and(|permission| permission.permission_type == Some(permission_type)) {
            return None;
        }
        Some(ShareChange {
            id: current.and_then(|permission| permission.id.clone()),
            aro: aro.into(),
            aro_foreign_key: aro_foreign_key.into(),
            permission_type: Some(permission_type),
            delete: None,
        })
    })
    .collect()
}

/// The secret as the user decrypts it, encrypted for each of `user_ids` and signed.
async fn secrets_for<H: HttpClient>(
    client: &PassboltSdk<H>,
    resource: &Resource,
    user_ids: &[String],
) -> Result<Vec<SecretPayload>, PassboltError> {
    let plaintext = client
        .decrypt_resource_secret_text(resource)
        .await?
        .ok_or_else(|| PassboltError::NotFound(format!("Secret of resource {}", resource.id)))?;
    let mut secrets = Vec::with_capacity(user_ids.len());
    for user_id in user_ids {
        let (public_key, _) = document::public_key_of(&client.get_user(user_id).await?)?;
        secrets.push(SecretPayload {
            user_id: user_id.clone(),
            data: crypto::sign_and_encrypt(&plaintext, &[client.user_signer()], &[&public_key])?,
        });
    }
    Ok(secrets)
}

/// Encrypt personal metadata for the shared metadata key, as sharing requires.
async fn move_metadata_to_the_shared_key<H: HttpClient>(
    client: &PassboltSdk<H>,
    resource: &Resource,
) -> Result<(), PassboltError> {
    let resource_type: ResourceType = client
        .resource_types()
        .await?
        .iter()
        .find(|resource_type| {
            resource.resource_type_id.as_deref() == Some(resource_type.id.as_str())
        })
        .cloned()
        .ok_or_else(|| PassboltError::InvalidArgument("Unknown resource type".into()))?;
    let metadata = client
        .decrypt_resource_metadata(resource)
        .await?
        .ok_or_else(|| PassboltError::InvalidArgument("The resource has no metadata".into()))?;
    let encrypted = client.encrypt_shared_metadata(&metadata).await?;
    let payload = UpdateResourcePayload {
        name: None,
        username: None,
        uri: None,
        description: None,
        resource_type_id: Some(resource_type.id),
        secrets: None,
        expired: None,
        metadata: Some(encrypted.metadata),
        metadata_key_id: Some(encrypted.metadata_key_id),
        metadata_key_type: Some(encrypted.metadata_key_type.into()),
    };
    client
        .update_resource(&resource.id, &payload)
        .await
        .map(drop)
}
