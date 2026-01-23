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

use std::collections::HashMap;

use serde_json::Value;

use crate::client::PassboltSdk;
use crate::crypto;
use crate::error::PassboltError;
use crate::http::HttpClient;
use crate::resource::document;
use crate::types::{
    Group, GroupMembershipChange, GroupSecretPayload, GroupUser, UpdateGroupPayload,
};

/// Update a group, as go-passbolt does: existing memberships change by their id, and new
/// members get the secrets of the group's resources, from the update dry-run.
///
/// Adding a member with the role they have is a no-op; removing a non-member is an error.
pub async fn update_group<H: HttpClient>(
    client: &PassboltSdk<H>,
    id: &str,
    name: Option<&str>,
    add_members: &[String],
    add_managers: &[String],
    remove_members: &[String],
) -> Result<Group, PassboltError> {
    let group = client.get_group(id).await?;
    let changes = membership_changes(
        &group.groups_users,
        add_members,
        add_managers,
        remove_members,
    )?;
    if changes.is_empty() && name.is_none() {
        return Ok(group);
    }
    let adds_members = changes.iter().any(|change| change.user_id.is_some());
    let mut payload = UpdateGroupPayload {
        name: name.map(String::from),
        groups_users: (!changes.is_empty()).then_some(changes),
        secrets: None,
    };
    if adds_members {
        let dry_run = client.update_group_dry_run(id, &payload).await?;
        payload.secrets = Some(secrets_needed(client, &dry_run).await?);
    }
    client.update_group(id, &payload).await
}

fn membership_changes(
    memberships: &[GroupUser],
    add_members: &[String],
    add_managers: &[String],
    remove_members: &[String],
) -> Result<Vec<GroupMembershipChange>, PassboltError> {
    let membership_of = |user_id: &str| {
        memberships
            .iter()
            .find(|membership| membership.user_id.as_deref() == Some(user_id))
    };
    let mut changes = Vec::new();
    // A manager is also a member: added once, as a manager.
    let additions = add_managers.iter().map(|user_id| (user_id, true)).chain(
        add_members
            .iter()
            .filter(|user_id| !add_managers.contains(user_id))
            .map(|user_id| (user_id, false)),
    );
    for (user_id, is_admin) in additions {
        match membership_of(user_id) {
            // Adding a member who is already one, manager included, changes nothing.
            Some(membership) if membership.is_admin == Some(is_admin) || !is_admin => {}
            Some(membership) => changes.push(GroupMembershipChange {
                id: membership.id.clone(),
                is_admin: Some(is_admin),
                ..GroupMembershipChange::default()
            }),
            None => changes.push(GroupMembershipChange {
                user_id: Some(user_id.clone()),
                is_admin: Some(is_admin),
                ..GroupMembershipChange::default()
            }),
        }
    }
    for user_id in remove_members {
        let membership = membership_of(user_id).ok_or_else(|| {
            PassboltError::InvalidArgument(format!("User {user_id} is not a member of the group"))
        })?;
        changes.push(GroupMembershipChange {
            id: membership.id.clone(),
            delete: Some(true),
            ..GroupMembershipChange::default()
        });
    }
    Ok(changes)
}

/// Each secret of `SecretsNeeded`, decrypted from the user's own copy in `Secrets` and
/// encrypted for the new member, signed.
async fn secrets_needed<H: HttpClient>(
    client: &PassboltSdk<H>,
    dry_run: &Value,
) -> Result<Vec<GroupSecretPayload>, PassboltError> {
    let field = |value: &Value, name: &str| value[name].as_str().unwrap_or_default().to_string();
    let own_secrets: HashMap<String, String> = dry_run["dry-run"]["Secrets"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|container| container["Secret"].as_array().cloned().unwrap_or_default())
        .map(|secret| (field(&secret, "resource_id"), field(&secret, "data")))
        .collect();
    let mut plaintexts: HashMap<String, String> = HashMap::new();
    let mut public_keys = HashMap::new();
    let mut secrets = Vec::new();
    for needed in dry_run["dry-run"]["SecretsNeeded"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let resource_id = field(&needed["Secret"], "resource_id");
        let user_id = field(&needed["Secret"], "user_id");
        if !plaintexts.contains_key(&resource_id) {
            let encrypted = own_secrets.get(&resource_id).ok_or_else(|| {
                PassboltError::Other(format!(
                    "The dry-run gave no secret of resource {resource_id}"
                ))
            })?;
            plaintexts.insert(resource_id.clone(), client.decrypt_text(encrypted)?);
        }
        if !public_keys.contains_key(&user_id) {
            let (public_key, _) = document::public_key_of(&client.get_user(&user_id).await?)?;
            public_keys.insert(user_id.clone(), public_key);
        }
        secrets.push(GroupSecretPayload {
            data: crypto::sign_and_encrypt(
                &plaintexts[&resource_id],
                &[client.user_signer()],
                &[&public_keys[&user_id]],
            )?,
            resource_id,
            user_id,
        });
    }
    Ok(secrets)
}
