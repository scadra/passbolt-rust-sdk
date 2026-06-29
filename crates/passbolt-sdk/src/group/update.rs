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
/// `members` and `managers` get that role, or lose their membership with `delete`. An empty
/// name keeps the current one. Giving a user the role they have, or removing a non-member, is
/// an error.
pub async fn update_group<H: HttpClient>(
    client: &PassboltSdk<H>,
    id: &str,
    name: Option<&str>,
    members: &[String],
    managers: &[String],
    delete: bool,
) -> Result<Group, PassboltError> {
    let name = name.filter(|name| !name.is_empty());
    let group = client.get_group(id).await?;
    let changes = membership_changes(&group.groups_users, members, managers, delete)?;
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
    members: &[String],
    managers: &[String],
    delete: bool,
) -> Result<Vec<GroupMembershipChange>, PassboltError> {
    let membership_of = |user_id: &str| {
        memberships
            .iter()
            .find(|membership| membership.user_id.as_deref() == Some(user_id))
    };
    // A user given as both member and manager is added once, as a manager.
    let operations = managers.iter().map(|user_id| (user_id, true)).chain(
        members
            .iter()
            .filter(|user_id| delete || !managers.contains(user_id))
            .map(|user_id| (user_id, false)),
    );
    let mut changes = Vec::new();
    for (user_id, is_admin) in operations {
        let change = match membership_of(user_id) {
            None if delete => {
                return Err(PassboltError::InvalidArgument(format!(
                    "cannot Delete User {user_id} as it has no membership"
                )))
            }
            None => GroupMembershipChange {
                user_id: Some(user_id.clone()),
                is_admin: Some(is_admin),
                ..GroupMembershipChange::default()
            },
            Some(membership) if !delete && membership.is_admin == Some(is_admin) => {
                return Err(PassboltError::InvalidArgument(format!(
                    "membership for User {user_id} already Exists with Same Role"
                )))
            }
            Some(membership) => GroupMembershipChange {
                id: membership.id.clone(),
                is_admin: (!delete).then_some(is_admin),
                delete: delete.then_some(true),
                ..GroupMembershipChange::default()
            },
        };
        changes.push(change);
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
            let (public_key, _) =
                document::public_key_of(client.openpgp(), &client.get_user(&user_id).await?)?;
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
