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

use anyhow::{Context, Result};
use clap::Args;

use crate::config::Config;
use crate::util::session;

#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Trust the server key or metadata key even if it changed since it was pinned: only once
    /// your administrator confirmed the change
    #[arg(long)]
    pub force: bool,
}

/// Pin the server key and save the settings given, as go-passbolt-cli's `verify` does: each
/// login then checks the server holds the key. Pins the shared metadata key too when the
/// account logs in without MFA.
pub async fn run(args: &VerifyArgs, config: &Config) -> Result<()> {
    let mut config = config.clone();
    session::require_credentials(&mut config)?;
    let private_key = passbolt_sdk::crypto::parse_private_key(&config.private_key_text()?)?;
    let http = session::http_client(&config)?;
    let base_url = config.server_address.trim_end_matches('/').to_string();

    let (fingerprint, server_public_key) = passbolt_sdk::auth::fetch_server_key(&http, &base_url)
        .await
        .context("setup Verification")?;
    if !config.server_public_key.is_empty() && !args.force {
        let pinned = passbolt_sdk::crypto::public_key_fingerprint(&config.server_public_key)?;
        refuse_change("server", &pinned, &fingerprint)?;
    }
    // The token pair go-passbolt-cli checks at each login, proved once here.
    let token = passbolt_sdk::auth::new_verify_token();
    let server_key = passbolt_sdk::crypto::parse_public_key(&server_public_key)?;
    let encrypted_token = passbolt_sdk::crypto::encrypt_message(token.as_bytes(), &[&server_key])?;
    passbolt_sdk::auth::verify_server(
        &http,
        &base_url,
        &private_key.fingerprint,
        &encrypted_token,
        &token,
    )
    .await
    .context("setup Verification")?;

    config.server_public_key = server_public_key;
    config.server_verify_token = token;
    config.server_verify_enc_token = encrypted_token;
    config.save()?;
    if config.debug {
        eprintln!("Server key {fingerprint} pinned: each login now checks the server holds it.");
    }

    pin_metadata_key(args, &mut config).await?;
    println!("Verification Enabled");
    Ok(())
}

/// Pin the active shared metadata key. A login that needs MFA, or any other failure to read
/// the key, leaves it unpinned: only a changed key is an error.
async fn pin_metadata_key(args: &VerifyArgs, config: &mut Config) -> Result<()> {
    let mut without_mfa = config.clone();
    without_mfa.mfa_mode = "none".into();
    let Ok(client) = session::get_client(&without_mfa).await else {
        return Ok(());
    };
    let metadata_keys = client.metadata_keys().await;
    client.logout().await;
    let Some(fingerprint) = metadata_keys
        .ok()
        .and_then(|keys| keys.active_fingerprint())
    else {
        return Ok(());
    };
    if !config.metadata_key_fingerprint.is_empty() && !args.force {
        refuse_change("metadata", &config.metadata_key_fingerprint, &fingerprint)?;
    }
    config.metadata_key_fingerprint.clone_from(&fingerprint);
    config.save()?;
    if config.debug {
        eprintln!("Metadata key {fingerprint} pinned: shared metadata is only encrypted for it.");
    }
    Ok(())
}
fn refuse_change(kind: &str, pinned: &str, current: &str) -> Result<()> {
    if pinned.eq_ignore_ascii_case(current) {
        return Ok(());
    }
    anyhow::bail!(
        "The {kind} key changed: {pinned} is pinned, the server now has {current}. Check the \
         change with your administrator, then run `passbolt verify --force` to trust the new key."
    )
}
