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
use crate::error::PassboltError;
use crate::http::HttpClient;
use crate::permission::{changes, grants};
use crate::types::{CreateFolderPayload, Folder, SharePayload};

/// Create a folder; in a parent folder, it then gets exactly the parent's permissions, as the
/// browser extension gives them.
pub async fn create_folder<H: HttpClient>(
    client: &PassboltSdk<H>,
    name: &str,
    folder_parent_id: Option<&str>,
) -> Result<Folder, PassboltError> {
    let folder_parent_id = folder_parent_id.filter(|folder_id| !folder_id.is_empty());
    let payload = CreateFolderPayload {
        name: name.to_string(),
        folder_parent_id: folder_parent_id.map(String::from),
    };
    let created = client.create_folder(&payload).await?;
    if let Some(parent_id) = folder_parent_id {
        let parent_permissions = client.get_folder_permissions(parent_id).await?;
        let current = client.get_folder_permissions(&created.id).await?;
        let changes = changes(&current, &grants(&parent_permissions));
        if !changes.is_empty() {
            let payload = SharePayload {
                permissions: changes,
                secrets: None,
            };
            client.share_folder(&created.id, &payload).await?;
        }
    }
    Ok(created)
}
