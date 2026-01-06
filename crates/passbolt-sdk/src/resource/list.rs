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

use crate::client::{PassboltSdk, ResourceQuery};
use crate::error::PassboltError;
use crate::filter::Filter;
use crate::http::HttpClient;
use crate::resource::filter::filter_resources;
use crate::resource::view::ResourceView;

/// List resources with their v5 metadata decrypted, and their secrets with `secret_workers`
/// (decryption threads, 0 for one per CPU).
///
/// `query.search` and `filters` apply to the decrypted fields: the server cannot search
/// encrypted v5 names. A resource that cannot be decrypted is listed with its `error`.
pub async fn list_resources<H: HttpClient>(
    client: &PassboltSdk<H>,
    query: ResourceQuery,
    filters: &[Filter],
    secret_workers: Option<usize>,
) -> Result<Vec<ResourceView>, PassboltError> {
    let search = query.search.clone();
    let resources = client.get_resources(query).await?;
    let resource_types = client.resource_types().await?;
    let mut secrets = match secret_workers {
        Some(workers) => {
            client
                .decrypt_secret_texts_batch(&resources, workers)
                .await?
        }
        None => std::collections::HashMap::default(),
    };
    let mut views = Vec::with_capacity(resources.len());
    let mut new_session_keys = Vec::new();
    // A resource that does not decrypt is listed with its error.
    for resource in resources {
        let id = resource.id.clone();
        let metadata = client
            .decrypt_resource_metadata_keeping_session_key(&resource)
            .await;
        let view = match metadata {
            Ok(Some((metadata, session_key))) => {
                if let Some(session_key) = session_key {
                    new_session_keys.push((id.clone(), session_key));
                }
                ResourceView::new(resource, Some(metadata), &resource_types)?
            }
            Ok(None) => ResourceView::new(resource, None, &resource_types)?,
            Err(error) => ResourceView::new(resource, None, &resource_types)?.with_error(&error),
        };
        let view = match secrets.remove(&id) {
            Some(Ok(secret)) if view.error.is_none() => view.with_secret(&secret)?,
            Some(Err(error)) if view.error.is_none() => view.with_error(&error),
            _ => view,
        };
        views.push(view);
    }
    // The next listing decrypts these faster; failing to save them only loses that.
    let _ = client.save_session_keys(&new_session_keys).await;
    if let Some(search) = search {
        let needle = search.to_lowercase();
        views.retain(|view| view.name.to_lowercase().contains(&needle));
    }
    Ok(filter_resources(views, filters))
}
