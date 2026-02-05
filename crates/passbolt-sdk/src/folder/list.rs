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

use crate::client::{FolderQuery, PassboltSdk};
use crate::error::PassboltError;
use crate::filter::Filter;
use crate::folder::filter::filter_folders;
use crate::http::HttpClient;
use crate::types::Folder;

pub async fn list_folders<H: HttpClient>(
    client: &PassboltSdk<H>,
    search: Option<String>,
    group_ids: Vec<String>,
    parent_folder_ids: Vec<String>,
    filters: &[Filter],
) -> Result<Vec<Folder>, PassboltError> {
    let mut folders = client
        .get_folders(FolderQuery {
            search,
            parent_folder_ids,
            ..Default::default()
        })
        .await?;
    // The folders any of the groups has a permission on.
    if !group_ids.is_empty() {
        folders.retain(|folder| {
            folder.permissions.iter().any(|permission| {
                permission.aro.as_deref() == Some("Group")
                    && permission
                        .aro_foreign_key
                        .as_ref()
                        .is_some_and(|group_id| group_ids.contains(group_id))
            })
        });
    }

    Ok(filter_folders(folders, filters))
}
