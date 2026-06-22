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

//! Prints a TypeScript module giving the SDK fixtures, serialized as the session returns them, the
//! types of `src/types.d.ts`: `tsc --strict` on it fails when the declarations and the SDK differ.
//!
//! ```sh
//! cargo run -q -p passbolt-wasm --example typescript_samples > samples.ts
//! cp crates/passbolt-wasm/src/types.d.ts .
//! tsc --strict --noEmit --module nodenext samples.ts
//! ```

use std::error::Error;
use std::fmt::Write;

use passbolt_sdk::resource::view::ResourceView;
use passbolt_sdk::transfer::{DeleteBlockers, ManagedGroup, OwnedItem};
use passbolt_sdk::types::{
    Aro, Comment, Favorite, Folder, Group, GroupDeleteDryRun, MetadataKeysSettings,
    MetadataTypesSettings, PasswordExpirySettings, Permission, Resource, ResourceMetadata,
    ResourceType, Tag, User,
};
use serde::Serialize;
use serde_json::Value;

const FIXTURES: &[(&str, &str)] = &[
    (
        "aros",
        include_str!("../../passbolt-sdk/tests/fixtures/data/aros.json"),
    ),
    (
        "comment",
        include_str!("../../passbolt-sdk/tests/fixtures/data/comment.json"),
    ),
    (
        "favorite",
        include_str!("../../passbolt-sdk/tests/fixtures/data/favorite.json"),
    ),
    (
        "folder",
        include_str!("../../passbolt-sdk/tests/fixtures/data/folder.json"),
    ),
    (
        "group",
        include_str!("../../passbolt-sdk/tests/fixtures/data/group.json"),
    ),
    (
        "group_dry_run",
        include_str!("../../passbolt-sdk/tests/fixtures/data/group_dry_run.json"),
    ),
    (
        "metadata_keys_settings",
        include_str!("../../passbolt-sdk/tests/fixtures/data/metadata_keys_settings.json"),
    ),
    (
        "metadata_types_settings",
        include_str!("../../passbolt-sdk/tests/fixtures/data/metadata_types_settings.json"),
    ),
    (
        "password_expiry_settings",
        include_str!("../../passbolt-sdk/tests/fixtures/data/password_expiry_settings.json"),
    ),
    (
        "permission",
        include_str!("../../passbolt-sdk/tests/fixtures/data/permission.json"),
    ),
    (
        "resource_metadata",
        include_str!("../../passbolt-sdk/tests/fixtures/data/resource_metadata.json"),
    ),
    (
        "resource_types",
        include_str!("../../passbolt-sdk/tests/fixtures/data/resource_types.json"),
    ),
    (
        "resource_v4",
        include_str!("../../passbolt-sdk/tests/fixtures/data/resource_v4.json"),
    ),
    (
        "resource_v5",
        include_str!("../../passbolt-sdk/tests/fixtures/data/resource_v5.json"),
    ),
    (
        "tag",
        include_str!("../../passbolt-sdk/tests/fixtures/data/tag.json"),
    ),
    (
        "users",
        include_str!("../../passbolt-sdk/tests/fixtures/data/users.json"),
    ),
];

/// The fixture `name`, read as the SDK reads the API's answer.
fn fixture<T: serde::de::DeserializeOwned>(name: &str) -> Result<T, Box<dyn Error>> {
    let (_, json) = FIXTURES
        .iter()
        .find(|(fixture_name, _)| *fixture_name == name)
        .ok_or_else(|| format!("no fixture {name}"))?;
    Ok(serde_json::from_str(json)?)
}

struct Samples(String);

impl Samples {
    /// `export const <name>: T.<type> = <value as the session returns it>;`
    fn add(
        &mut self,
        name: &str,
        type_name: &str,
        value: &impl Serialize,
    ) -> Result<(), Box<dyn Error>> {
        let json = serde_json::to_string_pretty(value)?;
        writeln!(self.0, "export const {name}: T.{type_name} = {json};\n")?;
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut samples = Samples(String::from("import type * as T from \"./types.js\";\n\n"));

    let resource_types: Vec<ResourceType> = fixture("resource_types")?;
    let resource: Resource = fixture("resource_v4")?;
    let resource_v5: Resource = fixture("resource_v5")?;
    let metadata: ResourceMetadata = fixture("resource_metadata")?;
    samples.add("resource", "Resource", &resource)?;
    samples.add("resourceV5", "Resource", &resource_v5)?;
    samples.add(
        "view",
        "ResourceView",
        &ResourceView::new(resource, None, &resource_types)?,
    )?;
    samples.add(
        "viewV5",
        "ResourceView",
        &ResourceView::new(resource_v5, Some(metadata), &resource_types)?,
    )?;
    samples.add("resourceTypes", "ResourceType[]", &resource_types)?;

    let folder: Folder = fixture("folder")?;
    samples.add(
        "tree",
        "FolderTreeNode[]",
        &passbolt_sdk::build_folder_tree(std::slice::from_ref(&folder)),
    )?;
    samples.add("folder", "Folder", &folder)?;

    let users: serde_json::Map<String, Value> = fixture("users")?;
    for (name, user) in users {
        let user: User = serde_json::from_value(user)?;
        samples.add(&format!("user_{name}"), "User", &user)?;
    }
    let group: Group = fixture("group")?;
    let permission: Permission = fixture("permission")?;
    samples.add(
        "blockers",
        "DeleteBlockers",
        &DeleteBlockers {
            resources: vec![OwnedItem {
                id: "resource".into(),
                permissions: vec![permission.clone()],
            }],
            folders: Vec::new(),
            groups: vec![ManagedGroup {
                id: group.id.clone(),
                name: group.name.clone(),
                groups_users: group.groups_users.clone(),
            }],
            groups_to_delete: vec!["group".into()],
        },
    )?;
    samples.add("group", "Group", &group)?;
    samples.add("permission", "Permission", &permission)?;
    samples.add(
        "groupDryRun",
        "GroupDeleteDryRun",
        &fixture::<GroupDeleteDryRun>("group_dry_run")?,
    )?;

    samples.add("tag", "Tag", &fixture::<Tag>("tag")?)?;
    samples.add("comment", "Comment", &fixture::<Comment>("comment")?)?;
    samples.add("favorite", "Favorite", &fixture::<Favorite>("favorite")?)?;
    samples.add("aros", "Aro[]", &fixture::<Vec<Aro>>("aros")?)?;
    samples.add(
        "passwordExpiry",
        "PasswordExpirySettings",
        &fixture::<PasswordExpirySettings>("password_expiry_settings")?,
    )?;
    samples.add(
        "metadataTypes",
        "MetadataTypesSettings",
        &fixture::<MetadataTypesSettings>("metadata_types_settings")?,
    )?;
    samples.add(
        "metadataKeys",
        "MetadataKeysSettings",
        &fixture::<MetadataKeysSettings>("metadata_keys_settings")?,
    )?;

    print!("{}", samples.0);
    Ok(())
}
