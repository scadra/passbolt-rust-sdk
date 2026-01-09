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

pub mod data;
pub mod fake;
pub mod keys;

use std::collections::BTreeSet;
use std::sync::Mutex;

use passbolt_sdk::{MfaProvider, PassboltError, PassboltSdk, SdkConfig};
use serde_json::Value;

pub use fake::FakePassbolt;
pub use keys::{ADA, BETTY, CAROL, ERIN, METADATA, SERVER};

pub const BASE_URL: &str = "https://passbolt.test";
pub const CSRF_TOKEN: &str = "csrf-test-token";

// Must match tests/fixtures/data.
pub const ADA_ID: &str = "8b6c3a10-0000-4000-8000-00000000a0da";
pub const BETTY_ID: &str = "8b6c3a10-0000-4000-8000-000000000be7";
pub const CAROL_ID: &str = "8b6c3a10-0000-4000-8000-0000000ca201";
pub const ERIN_ID: &str = "8b6c3a10-0000-4000-8000-00000000e121";
pub const GROUP_ID: &str = "9c7d4b20-0000-4000-8000-000000000960";
pub const RESOURCE_ID: &str = "7a5b2c30-0000-4000-8000-0000000000e1";
pub const FOLDER_ID: &str = "5f6e7d8c-0000-4000-8000-0000000000f1";

pub type Client = PassboltSdk<FakePassbolt>;

pub fn resource_path() -> String {
    format!("/resources/{RESOURCE_ID}.json")
}

pub fn ada_config() -> SdkConfig {
    SdkConfig {
        server_url: BASE_URL.into(),
        private_key_armored: ADA.private.into(),
        passphrase: ADA.passphrase.to_string().into(),
        mfa_mode: "none".into(),
        mfa_totp_token: String::new(),
        mfa_totp_offset: 0,
        mfa_retrys: 3,
        tls_skip_verify: false,
        tls_client_cert: String::new(),
        tls_client_private_key: String::new(),
        proxy: String::new(),
        server_public_key: String::new(),
        metadata_key_fingerprint: String::new(),
        server_verify_enc_token: String::new(),
        server_verify_token: String::new(),
    }
}

pub async fn login_ada(fake: &FakePassbolt) -> Client {
    PassboltSdk::login(fake.clone(), &ada_config(), None, 3)
        .await
        .unwrap()
}

/// `fake` serving the resource with `secret` and `permissions`, plus the directory.
pub fn fake_serving_resource(slug: &str, secret: &str, permissions: Value) -> FakePassbolt {
    let fake = FakePassbolt::new();
    fake.with_directory();
    fake.on("GET", &resource_path(), data::resource_v4(slug, secret));
    fake.on(
        "GET",
        &format!("/permissions/resource/{RESOURCE_ID}.json"),
        permissions,
    );
    fake
}

/// Ada as the only owner of the resource.
pub fn ada_owner_permissions() -> Value {
    serde_json::json!([data::permission("p-ada", "User", ADA_ID, 15)])
}

/// Armored secret sent for `user_id` in a request body.
pub fn secret_of<'a>(body: &'a Value, user_id: &str) -> &'a str {
    body["secrets"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|secret| secret["user_id"] == user_id)
        .and_then(|secret| secret["data"].as_str())
        .unwrap_or_else(|| panic!("no secret for {user_id} in {body}"))
}

pub fn secret_user_ids(body: &Value) -> BTreeSet<&str> {
    body["secrets"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|secret| secret["user_id"].as_str())
        .collect()
}

/// MFA provider returning `codes` in order.
pub struct FixedTotpCodes(Mutex<Vec<&'static str>>);

impl FixedTotpCodes {
    pub fn new(codes: &[&'static str]) -> Self {
        Self(Mutex::new(codes.iter().rev().copied().collect()))
    }
}

impl MfaProvider for FixedTotpCodes {
    fn get_totp_code(&self) -> Result<String, PassboltError> {
        self.0
            .lock()
            .unwrap()
            .pop()
            .map(str::to_string)
            .ok_or_else(|| PassboltError::Other("no more codes".into()))
    }
}
