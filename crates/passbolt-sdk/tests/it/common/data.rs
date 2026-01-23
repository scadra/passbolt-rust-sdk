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

//! API payloads from `tests/fixtures/data`, shaped like real Passbolt responses.
//! Encrypted fields are filled in with the fixture keys.

use passbolt_sdk::types::Resource;
use serde_json::{json, Value};

use super::keys::{by_name, TestKey, ADA};
use super::{ADA_ID, RESOURCE_ID};

macro_rules! fixture {
    ($file:literal) => {
        serde_json::from_str::<Value>(include_str!(concat!("../../fixtures/data/", $file))).unwrap()
    };
}

pub fn user(name: &str) -> Value {
    let key = by_name(name);
    let mut user = fixture!("users.json")[name].take();
    user["gpgkey"]["armored_key"] = key.public.into();
    user["gpgkey"]["fingerprint"] = key.fingerprint().into();
    user
}

/// Same user served with another person's public key.
pub fn user_with_key(name: &str, key: &TestKey) -> Value {
    let mut user = user(name);
    user["gpgkey"]["armored_key"] = key.public.into();
    user["gpgkey"]["fingerprint"] = key.fingerprint().into();
    user
}

pub fn users(names: &[&str]) -> Value {
    names.iter().map(|name| user(name)).collect()
}

pub fn roles() -> Value {
    fixture!("roles.json")
}

pub fn role_id(name: &str) -> String {
    roles()
        .as_array()
        .unwrap()
        .iter()
        .find(|role| role["name"] == name)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string()
}

pub fn resource_types() -> Value {
    fixture!("resource_types.json")
}

pub fn resource_type_id(slug: &str) -> String {
    resource_types()
        .as_array()
        .unwrap()
        .iter()
        .find(|resource_type| resource_type["slug"] == slug)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string()
}

/// v4 resource of type `slug` whose secret is encrypted for ada.
pub fn resource_v4(slug: &str, secret: &str) -> Value {
    let mut resource = fixture!("resource_v4.json");
    resource["resource_type_id"] = resource_type_id(slug).into();
    resource["secrets"] =
        json!([{ "user_id": ADA_ID, "resource_id": RESOURCE_ID, "data": ADA.encrypt(secret) }]);
    resource
}

pub fn resource(slug: &str, secret: &str) -> Resource {
    serde_json::from_value(resource_v4(slug, secret)).unwrap()
}

/// Decrypted v5 metadata, from `resource_metadata.json`.
pub fn metadata(name: &str) -> Value {
    let mut metadata = fixture!("resource_metadata.json");
    metadata["name"] = name.into();
    metadata
}

/// `/metadata/types/settings.json` of a server creating v5 resources by default.
pub fn metadata_types_settings() -> Value {
    fixture!("metadata_types_settings.json")
}

/// `/metadata/keys/settings.json`, the server defaults: personal keys allowed.
pub fn metadata_keys_settings() -> Value {
    fixture!("metadata_keys_settings.json")
}

/// The 400 body of `DELETE /users/{id}/dry-run.json` for a sole owner and manager.
pub fn user_delete_blockers() -> Value {
    fixture!("user_delete_dry_run_errors.json")
}

/// Decrypted v5-default secret, from `secret_v5_default.json`.
pub fn secret_v5_default() -> Value {
    fixture!("secret_v5_default.json")
}

/// v5 resource whose `metadata` is encrypted for `key`.
pub fn resource_v5(metadata: &Value, key: &TestKey, key_type: &str, key_id: &str) -> Resource {
    serde_json::from_value(resource_v5_value(metadata, key, key_type, key_id)).unwrap()
}

fn resource_v5_value(metadata: &Value, key: &TestKey, key_type: &str, key_id: &str) -> Value {
    let mut resource = fixture!("resource_v5.json");
    resource["metadata"] = key.encrypt(&metadata.to_string()).into();
    resource["metadata_key_type"] = key_type.into();
    resource["metadata_key_id"] = key_id.into();
    // The server only accepts personal metadata on a resource only its owner can access.
    resource["personal"] = (key_type == "user_key").into();
    if let Some(resource_type_id) = metadata["resource_type_id"].as_str() {
        resource["resource_type_id"] = resource_type_id.into();
    }
    resource
}

/// v5 resource of type `slug`, its metadata encrypted for `key`, its secret for ada.
pub fn resource_v5_with_secret(
    slug: &str,
    metadata: &Value,
    (key, key_type, key_id): (&TestKey, &str, &str),
    secret: &str,
) -> Value {
    let mut metadata = metadata.clone();
    metadata["resource_type_id"] = resource_type_id(slug).into();
    let mut resource = resource_v5_value(&metadata, key, key_type, key_id);
    resource["secrets"] =
        json!([{ "user_id": ADA_ID, "resource_id": RESOURCE_ID, "data": ADA.encrypt(secret) }]);
    resource
}

/// Decrypted `metadata_private_keys[].data`, as the server stores it.
pub fn metadata_private_key(key: &TestKey) -> String {
    let mut private_key = fixture!("metadata_private_key.json");
    private_key["fingerprint"] = key.fingerprint().into();
    private_key["armored_key"] = key.private.into();
    private_key.to_string()
}

/// `/metadata/keys.json` body: one share for ada per `(key id, metadata key)`.
pub fn metadata_keys(keys: &[(&str, &TestKey)]) -> Value {
    keys.iter()
        .map(|(key_id, key)| metadata_key(key_id, key, &ADA.encrypt(&metadata_private_key(key))))
        .collect()
}

/// `/metadata/keys.json` item for `key`, with ada's share `share_data`.
pub fn metadata_key(key_id: &str, key: &TestKey, share_data: &str) -> Value {
    let mut metadata_key = fixture!("metadata_key.json");
    metadata_key["id"] = key_id.into();
    metadata_key["fingerprint"] = key.fingerprint().into();
    metadata_key["armored_key"] = key.public.into();
    let share = &mut metadata_key["metadata_private_keys"][0];
    share["metadata_key_id"] = key_id.into();
    share["user_id"] = ADA_ID.into();
    share["data"] = share_data.into();
    metadata_key
}

pub fn permission(id: &str, aro: &str, aro_foreign_key: &str, permission_type: i32) -> Value {
    let mut permission = fixture!("permission.json");
    permission["id"] = id.into();
    permission["aro"] = aro.into();
    permission["aro_foreign_key"] = aro_foreign_key.into();
    permission["type"] = permission_type.into();
    permission
}

/// Folder with `permissions`, as `/folders/{id}.json?contain[permissions]=1` returns it.
pub fn folder(permissions: Value) -> Value {
    let mut folder = fixture!("folder.json");
    folder["permissions"] = permissions;
    folder
}

pub fn group() -> Value {
    fixture!("group.json")
}

pub fn group_membership_id(user_id: &str) -> String {
    group()["groups_users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|membership| membership["user_id"] == user_id)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string()
}

/// `PUT /groups/{id}/dry-run.json`: the group secret for ada, `secret` encrypted.
pub fn group_dry_run(secret: &str) -> Value {
    let mut dry_run = fixture!("group_dry_run.json");
    dry_run["dry-run"]["Secrets"][0]["Secret"][0]["data"] = ADA.encrypt(secret).into();
    dry_run
}

pub fn mfa_error() -> Value {
    fixture!("mfa_error.json")
}

pub fn auth_verify(server: &TestKey) -> Value {
    let mut verify_response = fixture!("auth_verify.json");
    verify_response["fingerprint"] = server.fingerprint().into();
    verify_response["keydata"] = server.public.into();
    verify_response
}

/// v4 resource as listed by `/resources.json`, without secret.
pub fn listed_resource(id: &str) -> Value {
    let mut resource = fixture!("resource_v4.json");
    resource["id"] = id.into();
    resource
}

pub fn listed_resources(ids: &[&str]) -> Value {
    ids.iter().map(|id| listed_resource(id)).collect()
}

pub fn tag(slug: &str) -> Value {
    let mut tag = fixture!("tag.json");
    tag["slug"] = slug.into();
    tag
}

pub fn comment() -> Value {
    fixture!("comment.json")
}

pub fn favorite() -> Value {
    fixture!("favorite.json")
}

pub fn aros() -> Value {
    fixture!("aros.json")
}

pub fn password_expiry_settings() -> Value {
    fixture!("password_expiry_settings.json")
}
