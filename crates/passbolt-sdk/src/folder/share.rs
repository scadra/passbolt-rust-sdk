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

use std::collections::BTreeSet;

use crate::client::{FolderQuery, PassboltSdk, ResourceQuery};
use crate::error::PassboltError;
use crate::http::HttpClient;
use crate::permission::{cascaded, changes, moved};
use crate::resource::share::{apply_changes, is_owner, requested_changes};
use crate::types::{Folder, ShareChange, SharePayload};

/// Share a folder with users and groups, or revoke their access (`permission_type == -1`).
///
/// Existing permissions are updated, not duplicated. With `with_content`, the change made on
/// the folder is copied onto the sub-folders and resources the user owns, as the browser
/// extension does: see [`cascaded`]. A branch stops at a folder the user does not own; nothing
/// is copied when the folder already had these permissions.
pub async fn share_folder<H: HttpClient>(
    client: &PassboltSdk<H>,
    id: &str,
    user_ids: &[String],
    group_ids: &[String],
    permission_type: i32,
    with_content: bool,
) -> Result<(), PassboltError> {
    let existing = client.get_folder_permissions(id).await?;
    let folder_changes = requested_changes(&existing, user_ids, group_ids, permission_type)?;
    if folder_changes.is_empty() {
        return Ok(());
    }
    client
        .share_folder(
            id,
            &SharePayload {
                permissions: folder_changes.clone(),
                secrets: None,
            },
        )
        .await?;
    if with_content {
        cascade(client, id, &folder_changes).await?;
    }
    Ok(())
}

/// Move a folder into `destination` (`None`: the root) with the permissions a move gives.
///
/// As the browser extension does (see [`moved`]), the change is then copied onto the content
/// the user owns. Only an owner can; the permissions are checked before the move, applied
/// after it.
pub async fn move_with_folder_permissions<H: HttpClient>(
    client: &PassboltSdk<H>,
    id: &str,
    destination: Option<&str>,
) -> Result<(), PassboltError> {
    let folder = client.get_folder(id).await?;
    if !is_owner(folder.permission.as_ref()) {
        return Err(PassboltError::InvalidArgument(format!(
            "Only an owner of folder {id} can give it the folder permissions"
        )));
    }
    let current = client.get_folder_permissions(id).await?;
    let parent = match folder.folder_parent_id.as_deref() {
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
        folder.permission.as_ref(),
    )?;
    client.move_folder(id, destination).await?;
    let folder_changes = changes(&current, &target);
    if folder_changes.is_empty() {
        return Ok(());
    }
    client
        .share_folder(
            id,
            &SharePayload {
                permissions: folder_changes.clone(),
                secrets: None,
            },
        )
        .await?;
    cascade(client, id, &folder_changes).await
}

/// Copy `folder_changes`, made on the folder `id`, onto the sub-folders and resources below it
/// the user owns.
pub(crate) async fn cascade<H: HttpClient>(
    client: &PassboltSdk<H>,
    id: &str,
    folder_changes: &[ShareChange],
) -> Result<(), PassboltError> {
    let folders = client.get_folders(FolderQuery::default()).await?;
    let owned_folders = owned_descendants(id, &folders);
    for folder_id in &owned_folders {
        let permissions = client.get_folder_permissions(folder_id).await?;
        let changes = cascaded(&permissions, folder_changes);
        if !changes.is_empty() {
            let payload = SharePayload {
                permissions: changes,
                secrets: None,
            };
            client.share_folder(folder_id, &payload).await?;
        }
    }

    let mut parent_ids: Vec<String> = owned_folders.into_iter().collect();
    parent_ids.push(id.to_string());
    let resources = client
        .get_resources(ResourceQuery {
            folder_ids: parent_ids,
            ..ResourceQuery::default()
        })
        .await?;
    for resource in resources
        .iter()
        .filter(|resource| is_owner(resource.permission.as_ref()))
    {
        let permissions = client.get_resource_permissions(&resource.id).await?;
        let changes = cascaded(&permissions, folder_changes);
        if !changes.is_empty() {
            apply_changes(client, &resource.id, changes).await?;
        }
    }
    Ok(())
}

/// The folders below `root` the user owns, a branch stopping at the first one they do not own.
fn owned_descendants(root: &str, folders: &[Folder]) -> BTreeSet<String> {
    let mut owned = BTreeSet::new();
    let mut parents = vec![root.to_string()];
    while let Some(parent) = parents.pop() {
        for child in folders
            .iter()
            .filter(|folder| folder.folder_parent_id.as_deref() == Some(parent.as_str()))
        {
            // A cycle in the parent links must not loop forever.
            if is_owner(child.permission.as_ref())
                && child.id != root
                && owned.insert(child.id.clone())
            {
                parents.push(child.id.clone());
            }
        }
    }
    owned
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::permission::OWNER;

    fn folder(id: &str, parent: Option<&str>, permission_type: i32) -> Folder {
        serde_json::from_value(json!({
            "id": id,
            "name": id,
            "folder_parent_id": parent,
            "created": null,
            "modified": null,
            "permission": {"type": permission_type}
        }))
        .unwrap()
    }

    #[test]
    fn test_owned_descendants_stop_at_a_folder_not_owned() {
        let folders = [
            folder("child", Some("root"), OWNER),
            folder("grandchild", Some("child"), OWNER),
            folder("read-only", Some("root"), 1),
            folder("below-read-only", Some("read-only"), OWNER),
            folder("elsewhere", None, OWNER),
        ];

        let owned = owned_descendants("root", &folders);

        assert_eq!(owned, BTreeSet::from(["child".into(), "grandchild".into()]));
    }

    #[test]
    fn test_owned_descendants_end_on_a_cycle() {
        let folders = [folder("a", Some("b"), OWNER), folder("b", Some("a"), OWNER)];

        assert_eq!(
            owned_descendants("a", &folders),
            BTreeSet::from(["b".into()])
        );
    }
}
