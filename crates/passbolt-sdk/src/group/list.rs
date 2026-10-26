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

use crate::client::{GroupQuery, PassboltSdk};
use crate::error::PassboltError;
use crate::filter::Filter;
use crate::group::filter::filter_groups;
use crate::http::HttpClient;
use crate::types::Group;

pub async fn list_groups<H: HttpClient>(
    client: &PassboltSdk<H>,
    user_ids: Vec<String>,
    manager_ids: Vec<String>,
    filters: &[Filter],
) -> Result<Vec<Group>, PassboltError> {
    let query = GroupQuery {
        user_ids,
        manager_ids,
        ..Default::default()
    };
    let groups = client.get_groups(query).await?;
    Ok(filter_groups(groups, filters))
}
