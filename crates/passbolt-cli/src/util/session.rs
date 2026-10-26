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
use passbolt_sdk::{AuthError, PassboltError};

use crate::config::Config;
use crate::util::mfa::{TerminalMfaProvider, INTERACTIVE_ATTEMPTS};

pub type Client = passbolt_sdk::PassboltSdk<passbolt_sdk::NativeHttpClient>;

/// go-passbolt-cli's checks before a login, in its order and with its messages: the server
/// address, the private key, then the password, asked for when it is not given.
pub fn require_credentials(config: &mut Config) -> Result<()> {
    if config.server_address.is_empty() {
        anyhow::bail!("serverAddress is not defined");
    }
    if config.user_private_key.is_empty() {
        anyhow::bail!("userPrivateKey is not defined");
    }
    if config.user_password.is_empty() {
        config.user_password =
            crate::util::password::prompt_secret("Enter Password:").context("reading Password")?;
    }
    Ok(())
}

/// The HTTP client of the settings, printing the requests with `--debug`.
pub fn http_client(config: &Config) -> Result<passbolt_sdk::NativeHttpClient> {
    Ok(passbolt_sdk::NativeHttpClient::new(&config.http_config()?)?.with_debug(config.debug))
}

/// Log in. The MFA modes are go-passbolt-cli's: `interactive-totp` asks for 3 codes,
/// `noninteractive-totp` generates up to `mfa_retrys` codes (at most 3: the server disables
/// the account after 4 wrong codes), and any other mode answers no MFA challenge.
pub async fn get_client(config: &Config) -> Result<Client> {
    let sdk_config = config.to_sdk_config()?;
    let http = http_client(config)?;

    let interactive = sdk_config.mfa_mode == "interactive-totp";
    let (mfa_provider, max_attempts): (Option<Box<dyn passbolt_sdk::MfaProvider>>, u32) =
        match sdk_config.mfa_mode.as_str() {
            "interactive-totp" => (Some(Box::new(TerminalMfaProvider)), INTERACTIVE_ATTEMPTS),
            // `non-interactive-totp` is this CLI's former spelling.
            "noninteractive-totp" | "non-interactive-totp" => (
                Some(Box::new(passbolt_sdk::mfa::TotpProvider::new(
                    &sdk_config.mfa_totp_token,
                    sdk_config.mfa_totp_offset,
                    config.mfa_retry_delay()?,
                )?)),
                sdk_config.mfa_retrys.max(1),
            ),
            _ => (None, 1),
        };

    passbolt_sdk::PassboltSdk::login(http, &sdk_config, mfa_provider, max_attempts)
        .await
        .map_err(|error| match error {
            PassboltError::Auth(AuthError::MfaFailed { message, .. }) if interactive => {
                anyhow::anyhow!("failed MFA Challenge {INTERACTIVE_ATTEMPTS} times: {message}")
            }
            error => anyhow::Error::from(error),
        })
        .context("logging in")
}

/// Save the session keys found during the command, then log out, as go-passbolt-cli does.
pub async fn finish(client: &Client) {
    if client.pending_session_keys_count() > 0 {
        if let Err(error) = client.save_pending_session_keys().await {
            eprintln!("Warning: failed to save session keys: {error}");
        }
    }
    let saved = client.saved_session_keys_count();
    if saved > 0 {
        eprintln!("Saved {saved} session keys to server");
    }
    client.logout().await;
}
