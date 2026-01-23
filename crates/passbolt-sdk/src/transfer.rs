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

//! What blocks deleting a user or a group, and the transfer of ownership that unblocks it, as
//! the browser extension offers it.

use serde::Serialize;
use serde_json::Value;

use crate::error::PassboltError;
use crate::types::{GroupUser, Permission};

/// A shared resource or folder only the deleted user (or group) owns, with its permissions.
#[derive(Debug, Clone, Serialize)]
pub struct OwnedItem {
    pub id: String,
    pub permissions: Vec<Permission>,
}

/// A group with other members that only the deleted user manages, with its memberships.
#[derive(Debug, Clone, Serialize)]
pub struct ManagedGroup {
    pub id: String,
    pub name: String,
    pub groups_users: Vec<GroupUser>,
}

/// What the server's delete dry-run reports: each item needs a new owner, each group a new
/// manager, before the deletion goes through.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DeleteBlockers {
    pub resources: Vec<OwnedItem>,
    pub folders: Vec<OwnedItem>,
    pub groups: Vec<ManagedGroup>,
    /// Groups the deleted user is the only member of: deleted with them.
    pub groups_to_delete: Vec<String>,
}

/// The new owners and managers sent with the deletion.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Transfer {
    pub owners: Vec<OwnerTransfer>,
    pub managers: Vec<ManagerTransfer>,
}

/// The permission to raise to owner, on the item `aco_foreign_key`.
#[derive(Debug, Clone, Serialize)]
pub struct OwnerTransfer {
    pub id: String,
    pub aco_foreign_key: String,
}

/// The membership to make manager, in the group `group_id`.
#[derive(Debug, Clone, Serialize)]
pub struct ManagerTransfer {
    pub id: String,
    pub group_id: String,
}

impl DeleteBlockers {
    /// Read the dry-run `body`: `errors` (what blocks) and `groups_to_delete`.
    pub(crate) fn from_body(body: &Value) -> Result<Self, PassboltError> {
        let items = |pointer: &str| -> Result<Vec<OwnedItem>, PassboltError> {
            body.pointer(pointer)
                .and_then(Value::as_array)
                .map_or(&[][..], Vec::as_slice)
                .iter()
                .map(|item| {
                    Ok(OwnedItem {
                        id: id_of(item)?,
                        permissions: serde_json::from_value(
                            item.get("permissions").cloned().unwrap_or_default(),
                        )
                        .unwrap_or_default(),
                    })
                })
                .collect()
        };
        let groups = body
            .pointer("/errors/groups/sole_manager")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice)
            .iter()
            .map(|group| {
                Ok(ManagedGroup {
                    id: id_of(group)?,
                    name: group["name"].as_str().unwrap_or_default().to_string(),
                    groups_users: serde_json::from_value(
                        group.get("groups_users").cloned().unwrap_or_default(),
                    )
                    .unwrap_or_default(),
                })
            })
            .collect::<Result<_, PassboltError>>()?;
        let groups_to_delete = body
            .get("groups_to_delete")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice)
            .iter()
            .filter_map(|group| group["id"].as_str().map(String::from))
            .collect();
        Ok(Self {
            resources: items("/errors/resources/sole_owner")?,
            folders: items("/errors/folders/sole_owner")?,
            groups,
            groups_to_delete,
        })
    }

    /// Nothing blocks the deletion.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.resources.is_empty() && self.folders.is_empty() && self.groups.is_empty()
    }

    /// Everything to `successor_id`, a user or a group: owner of each item, manager of each
    /// group. The successor must already have access to each item and belong to each group.
    pub fn transfer_to(&self, successor_id: &str) -> Result<Transfer, PassboltError> {
        let mut owners = Vec::new();
        for (kind, items) in [("resource", &self.resources), ("folder", &self.folders)] {
            for item in items {
                let permission_id = item
                    .permissions
                    .iter()
                    .find(|permission| permission.aro_foreign_key.as_deref() == Some(successor_id))
                    .and_then(|permission| permission.id.clone())
                    .ok_or_else(|| {
                        PassboltError::InvalidArgument(format!(
                            "{successor_id} has no access to the {kind} {}: share it with them \
                             first",
                            item.id
                        ))
                    })?;
                owners.push(OwnerTransfer {
                    id: permission_id,
                    aco_foreign_key: item.id.clone(),
                });
            }
        }
        let mut managers = Vec::new();
        for group in &self.groups {
            let membership_id = group
                .groups_users
                .iter()
                .find(|membership| membership.user_id.as_deref() == Some(successor_id))
                .and_then(|membership| membership.id.clone())
                .ok_or_else(|| {
                    PassboltError::InvalidArgument(format!(
                        "{successor_id} is not a member of the group {}: add them first",
                        group.name
                    ))
                })?;
            managers.push(ManagerTransfer {
                id: membership_id,
                group_id: group.id.clone(),
            });
        }
        Ok(Transfer { owners, managers })
    }
}

fn id_of(item: &Value) -> Result<String, PassboltError> {
    item["id"]
        .as_str()
        .map(String::from)
        .ok_or_else(|| PassboltError::Other("A blocking item without id".into()))
}
