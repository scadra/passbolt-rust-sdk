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

//! Permission changes as the browser extension calculates them: from what an item has to what
//! it must have, a folder change copied onto its content, and the permissions of a moved item.

use crate::error::PassboltError;
use crate::types::{Permission, ShareChange};

pub const OWNER: i32 = 15;

/// What an ARO (user or group) may do on an item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub aro: String,
    pub aro_foreign_key: String,
    pub permission_type: i32,
}

impl Grant {
    fn of(permission: &Permission) -> Option<Self> {
        Some(Self {
            aro: permission.aro.clone()?,
            aro_foreign_key: permission.aro_foreign_key.clone()?,
            permission_type: permission.permission_type?,
        })
    }

    fn is_for(&self, aro: &str, aro_foreign_key: &str) -> bool {
        self.aro == aro && self.aro_foreign_key == aro_foreign_key
    }
}

/// The grants of `permissions`, those missing a field left out.
#[must_use]
pub fn grants(permissions: &[Permission]) -> Vec<Grant> {
    permissions.iter().filter_map(Grant::of).collect()
}

fn find<'a>(
    permissions: &'a [Permission],
    aro: &str,
    aro_foreign_key: &str,
) -> Option<&'a Permission> {
    permissions.iter().find(|permission| {
        permission.aro.as_deref() == Some(aro)
            && permission.aro_foreign_key.as_deref() == Some(aro_foreign_key)
    })
}

/// The changes giving an item with `current` permissions exactly `target`: new grants, type
/// updates and removals (`PermissionChangesCollection.calculateChanges`).
#[must_use]
pub fn changes(current: &[Permission], target: &[Grant]) -> Vec<ShareChange> {
    let mut changes = Vec::new();
    for grant in target {
        match find(current, &grant.aro, &grant.aro_foreign_key) {
            Some(permission) if permission.permission_type == Some(grant.permission_type) => {}
            existing => changes.push(ShareChange {
                id: existing.and_then(|permission| permission.id.clone()),
                aro: grant.aro.clone(),
                aro_foreign_key: grant.aro_foreign_key.clone(),
                permission_type: Some(grant.permission_type),
                delete: None,
            }),
        }
    }
    for permission in current {
        let Some(grant) = Grant::of(permission) else {
            continue;
        };
        if !target
            .iter()
            .any(|kept| kept.is_for(&grant.aro, &grant.aro_foreign_key))
        {
            changes.push(ShareChange {
                id: permission.id.clone(),
                aro: grant.aro,
                aro_foreign_key: grant.aro_foreign_key,
                permission_type: None,
                delete: Some(true),
            });
        }
    }
    changes
}

/// The change made on a folder, copied onto an item it contains with `item` permissions.
///
/// As `CalculatePermissionsChangesService._calculateCascaded` does: an ARO the folder change added,
/// updated or removed gets the same on the item, but a new grant only reaches an ARO the item
/// did not have; everybody else keeps their access. An item the copy would leave without owner
/// keeps its permissions: no change.
#[must_use]
pub fn cascaded(item: &[Permission], folder_changes: &[ShareChange]) -> Vec<ShareChange> {
    let change_for = |grant: &Grant| {
        folder_changes.iter().find(|change| {
            change.aro == grant.aro && change.aro_foreign_key == grant.aro_foreign_key
        })
    };
    let mut resulting = Vec::new();
    for grant in grants(item) {
        match change_for(&grant) {
            None => resulting.push(grant),
            Some(change) if change.delete == Some(true) => {}
            Some(change) => resulting.push(Grant {
                permission_type: change.permission_type.unwrap_or(grant.permission_type),
                ..grant
            }),
        }
    }
    for change in folder_changes {
        let created = change.id.is_none() && change.delete != Some(true);
        if created && find(item, &change.aro, &change.aro_foreign_key).is_none() {
            if let Some(permission_type) = change.permission_type {
                resulting.push(Grant {
                    aro: change.aro.clone(),
                    aro_foreign_key: change.aro_foreign_key.clone(),
                    permission_type,
                });
            }
        }
    }
    if !resulting.iter().any(|grant| grant.permission_type == OWNER) {
        return Vec::new();
    }
    changes(item, &resulting)
}

/// The permissions an item moved from `parent` into `destination` ends up with.
///
/// As `PermissionsCollection.calculateMovedPermissions` gives them: the ones it did not get from
/// the folder it leaves, plus the destination's, the higher level winning. Moved to the root,
/// the operator keeps their own `operator` permission.
pub fn moved(
    item: &[Permission],
    parent: Option<&[Permission]>,
    destination: Option<&[Permission]>,
    operator: Option<&Permission>,
) -> Result<Vec<Grant>, PassboltError> {
    let parent = parent.map(grants).unwrap_or_default();
    let mut target: Vec<Grant> = grants(item)
        .into_iter()
        .filter(|grant| {
            !parent.iter().any(|inherited| {
                inherited.is_for(&grant.aro, &grant.aro_foreign_key)
                    && inherited.permission_type >= grant.permission_type
            })
        })
        .collect();
    let mut add_or_raise = |grant: Grant| match target
        .iter_mut()
        .find(|kept| kept.is_for(&grant.aro, &grant.aro_foreign_key))
    {
        Some(kept) => kept.permission_type = kept.permission_type.max(grant.permission_type),
        None => target.push(grant),
    };
    match destination {
        Some(destination) => grants(destination).into_iter().for_each(&mut add_or_raise),
        None => {
            if let Some(grant) = operator.and_then(Grant::of) {
                add_or_raise(grant);
            }
        }
    }
    if !target.iter().any(|grant| grant.permission_type == OWNER) {
        return Err(PassboltError::InvalidArgument(
            "The move would leave the item without owner".into(),
        ));
    }
    Ok(target)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn permission(id: &str, aro: &str, aro_foreign_key: &str, permission_type: i32) -> Permission {
        serde_json::from_value(json!({
            "id": id, "aro": aro, "aro_foreign_key": aro_foreign_key, "type": permission_type,
            "created": null, "modified": null
        }))
        .unwrap()
    }

    fn user(id: &str, aro_foreign_key: &str, permission_type: i32) -> Permission {
        permission(id, "User", aro_foreign_key, permission_type)
    }

    fn grant(aro_foreign_key: &str, permission_type: i32) -> Grant {
        Grant {
            aro: "User".into(),
            aro_foreign_key: aro_foreign_key.into(),
            permission_type,
        }
    }

    fn created(aro_foreign_key: &str, permission_type: i32) -> ShareChange {
        ShareChange {
            id: None,
            aro: "User".into(),
            aro_foreign_key: aro_foreign_key.into(),
            permission_type: Some(permission_type),
            delete: None,
        }
    }

    fn updated(id: &str, aro_foreign_key: &str, permission_type: i32) -> ShareChange {
        ShareChange {
            id: Some(id.into()),
            ..created(aro_foreign_key, permission_type)
        }
    }

    fn deleted(id: &str, aro_foreign_key: &str) -> ShareChange {
        ShareChange {
            id: Some(id.into()),
            aro: "User".into(),
            aro_foreign_key: aro_foreign_key.into(),
            permission_type: None,
            delete: Some(true),
        }
    }

    /// `(aro foreign key, type or "delete", has id)` of each change, for comparison.
    fn summary(changes: &[ShareChange]) -> Vec<(String, Option<i32>, bool)> {
        let mut summary: Vec<_> = changes
            .iter()
            .map(|change| {
                (
                    change.aro_foreign_key.clone(),
                    change.permission_type,
                    change.id.is_some(),
                )
            })
            .collect();
        summary.sort();
        summary
    }

    #[test]
    fn test_changes_add_update_and_remove_to_reach_the_target() {
        let current = [
            user("p-ada", "ada", OWNER),
            user("p-betty", "betty", 1),
            user("p-carol", "carol", 7),
        ];

        let changes = changes(
            &current,
            &[grant("ada", OWNER), grant("betty", 7), grant("erin", 1)],
        );

        assert_eq!(
            summary(&changes),
            [
                ("betty".into(), Some(7), true),
                ("carol".into(), None, true),
                ("erin".into(), Some(1), false)
            ]
        );
    }

    #[test]
    fn test_no_change_when_the_target_is_already_there() {
        let current = [user("p-ada", "ada", OWNER)];

        assert!(changes(&current, &[grant("ada", OWNER)]).is_empty());
    }

    #[test]
    fn test_a_new_grant_on_the_folder_reaches_items_without_access() {
        let item = [user("p-ada", "ada", OWNER)];

        let cascaded = cascaded(&item, &[created("betty", 1)]);

        assert_eq!(summary(&cascaded), [("betty".into(), Some(1), false)]);
    }

    #[test]
    fn test_a_new_grant_on_the_folder_sets_the_level_of_an_item_access() {
        // Betty had no access to the folder but updates this item: she now reads it, as the
        // folder gives.
        let item = [user("p-ada", "ada", OWNER), user("p-betty", "betty", 7)];

        let cascaded = cascaded(&item, &[created("betty", 1)]);

        assert_eq!(summary(&cascaded), [("betty".into(), Some(1), true)]);
    }

    #[test]
    fn test_an_update_on_the_folder_only_reaches_items_the_aro_has() {
        let with_betty = [
            user("p-ada", "ada", OWNER),
            user("p-betty-item", "betty", 1),
        ];
        let without_betty = [user("p-ada", "ada", OWNER)];
        let folder_change = [updated("p-betty-folder", "betty", 7)];

        assert_eq!(
            summary(&cascaded(&with_betty, &folder_change)),
            [("betty".into(), Some(7), true)]
        );
        assert!(cascaded(&without_betty, &folder_change).is_empty());
    }

    #[test]
    fn test_the_item_permission_id_is_used_not_the_folder_one() {
        let item = [
            user("p-ada", "ada", OWNER),
            user("p-betty-item", "betty", 1),
        ];

        let cascaded = cascaded(&item, &[updated("p-betty-folder", "betty", 7)]);

        assert_eq!(cascaded[0].id.as_deref(), Some("p-betty-item"));
    }

    #[test]
    fn test_a_removal_on_the_folder_removes_the_item_permission() {
        let item = [
            user("p-ada", "ada", OWNER),
            user("p-betty-item", "betty", 1),
        ];

        let cascaded = cascaded(&item, &[deleted("p-betty-folder", "betty")]);

        assert_eq!(summary(&cascaded), [("betty".into(), None, true)]);
        assert_eq!(cascaded[0].id.as_deref(), Some("p-betty-item"));
    }

    #[test]
    fn test_an_item_the_change_would_leave_without_owner_is_left_alone() {
        // Betty alone owns the item; the folder change removes her.
        let item = [
            user("p-betty-item", "betty", OWNER),
            user("p-ada", "ada", 7),
        ];

        assert!(cascaded(&item, &[deleted("p-betty-folder", "betty")]).is_empty());
    }

    #[test]
    fn test_a_group_change_does_not_touch_a_user_of_the_same_id() {
        let item = [user("p-ada", "ada", OWNER), user("p-same", "same-id", 1)];
        let group_change = ShareChange {
            aro: "Group".into(),
            ..deleted("p-group", "same-id")
        };

        assert!(cascaded(&item, &[group_change]).is_empty());
    }

    #[test]
    fn test_moving_drops_what_the_old_folder_gave_and_adds_the_destination() {
        let item = [
            user("p-ada", "ada", OWNER),
            user("p-betty", "betty", 1),
            user("p-carol", "carol", 7),
        ];
        let parent = [user("f-ada", "ada", OWNER), user("f-betty", "betty", 1)];
        let destination = [user("d-ada", "ada", OWNER), user("d-erin", "erin", 7)];

        let target = moved(&item, Some(&parent), Some(&destination), None).unwrap();

        // Carol's access came from elsewhere than the old folder: it stays.
        let mut target: Vec<_> = target
            .into_iter()
            .map(|grant| (grant.aro_foreign_key, grant.permission_type))
            .collect();
        target.sort();
        assert_eq!(
            target,
            [
                ("ada".into(), OWNER),
                ("carol".into(), 7),
                ("erin".into(), 7)
            ]
        );
    }

    #[test]
    fn test_moving_keeps_an_access_higher_than_the_old_folder_gave() {
        let item = [user("p-ada", "ada", OWNER), user("p-betty", "betty", 7)];
        let parent = [user("f-ada", "ada", OWNER), user("f-betty", "betty", 1)];
        let destination = [user("d-ada", "ada", OWNER)];

        let target = moved(&item, Some(&parent), Some(&destination), None).unwrap();

        assert!(target.contains(&grant("betty", 7)));
    }

    #[test]
    fn test_moving_never_lowers_an_access() {
        let item = [user("p-ada", "ada", OWNER), user("p-betty", "betty", 7)];
        let destination = [user("d-ada", "ada", OWNER), user("d-betty", "betty", 1)];

        let target = moved(&item, None, Some(&destination), None).unwrap();

        assert!(target.contains(&grant("betty", 7)));
    }

    #[test]
    fn test_moving_to_the_root_keeps_the_operator() {
        let item = [user("p-ada", "ada", OWNER), user("p-betty", "betty", 1)];
        let parent = [user("f-ada", "ada", OWNER), user("f-betty", "betty", 1)];

        let target = moved(&item, Some(&parent), None, Some(&item[0])).unwrap();

        assert_eq!(target, [grant("ada", OWNER)]);
    }

    #[test]
    fn test_a_move_leaving_no_owner_is_refused() {
        let item = [user("p-ada", "ada", OWNER)];
        let parent = [user("f-ada", "ada", OWNER)];
        let destination = [user("d-betty", "betty", 7)];

        assert!(moved(&item, Some(&parent), Some(&destination), None).is_err());
    }
}
