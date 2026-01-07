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

use anyhow::Result;
use clap::Args;

use crate::config::Config;

#[derive(Args, Debug)]
pub struct VerifyArgs {}

/// Pin the server public key, once the server proved it holds the private key, then the
/// active shared metadata key: new shared metadata is never encrypted for another one.
pub async fn run(_args: &VerifyArgs, config: &Config) -> Result<()> {
    let private_key = passbolt_sdk::crypto::parse_private_key(&config.private_key_text()?)?;
    let http = passbolt_sdk::NativeHttpClient::new(&config.http_config()?)?;
    let base_url = config.server_address.trim_end_matches('/');

    let (fingerprint, server_public_key) =
        passbolt_sdk::auth::fetch_server_key(&http, base_url).await?;
    passbolt_sdk::auth::check_server_identity(
        &http,
        base_url,
        &private_key.fingerprint,
        &server_public_key,
        "",
        "",
    )
    .await?;
    Config::save_server_public_key(&server_public_key)?;

    println!("Server key {fingerprint} pinned: each login now checks the server holds it.");

    let client = crate::util::session::get_client(config).await?;
    let metadata_keys = client.metadata_keys().await;
    client.logout().await;
    match metadata_keys
        .ok()
        .and_then(|keys| keys.active_fingerprint())
    {
        Some(fingerprint) => {
            Config::save_metadata_key_fingerprint(&fingerprint)?;
            println!(
                "Metadata key {fingerprint} pinned: shared metadata is only encrypted for it."
            );
        }
        None => println!("No shared metadata key to pin."),
    }
    Ok(())
}
