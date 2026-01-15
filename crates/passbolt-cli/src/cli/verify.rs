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
pub struct VerifyArgs {
    /// Trust the server key or metadata key even if it changed since it was pinned: only once
    /// your administrator confirmed the change
    #[arg(long)]
    pub force: bool,
}

/// Pin the server public key, once the server proved it holds the private key, then the
/// active shared metadata key: new shared metadata is never encrypted for another one.
/// A pinned key that changed is kept unless `--force` is given.
pub async fn run(args: &VerifyArgs, config: &Config) -> Result<()> {
    let private_key = passbolt_sdk::crypto::parse_private_key(&config.private_key_text()?)?;
    let http = passbolt_sdk::NativeHttpClient::new(&config.http_config()?)?;
    let base_url = config.server_address.trim_end_matches('/');

    let (fingerprint, server_public_key) =
        passbolt_sdk::auth::fetch_server_key(&http, base_url).await?;
    if !config.server_public_key.is_empty() && !args.force {
        let pinned = passbolt_sdk::crypto::public_key_fingerprint(&config.server_public_key)?;
        refuse_change("server", &pinned, &fingerprint)?;
    }
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

    // Log in with the key just pinned, not the one replaced.
    let mut config = config.clone();
    config.server_public_key = server_public_key;
    config.server_verify_token.clear();
    config.server_verify_enc_token.clear();
    let client = crate::util::session::get_client(&config).await?;
    let metadata_keys = client.metadata_keys().await;
    client.logout().await;
    let active = match metadata_keys {
        Ok(keys) => keys.active_fingerprint(),
        Err(error) => {
            anyhow::bail!("Could not read the shared metadata keys, none pinned: {error}")
        }
    };
    match active {
        Some(fingerprint) => {
            if !config.metadata_key_fingerprint.is_empty() && !args.force {
                refuse_change("metadata", &config.metadata_key_fingerprint, &fingerprint)?;
            }
            Config::save_metadata_key_fingerprint(&fingerprint)?;
            println!(
                "Metadata key {fingerprint} pinned: shared metadata is only encrypted for it."
            );
        }
        None => println!("No shared metadata key to pin."),
    }
    Ok(())
}

/// Fail when the `pinned` key of `kind` is not the `current` one.
fn refuse_change(kind: &str, pinned: &str, current: &str) -> Result<()> {
    if pinned.eq_ignore_ascii_case(current) {
        return Ok(());
    }
    anyhow::bail!(
        "The {kind} key changed: {pinned} is pinned, the server now has {current}. Check the \
         change with your administrator, then run `passbolt verify --force` to trust the new key."
    )
}
