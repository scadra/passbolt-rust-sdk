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

use crate::config::Config;

pub type Client = passbolt_sdk::PassboltSdk<passbolt_sdk::NativeHttpClient>;

/// Build a client from the loaded config, performing login.
pub async fn get_client(config: &Config) -> Result<Client> {
    let sdk_config = config.to_sdk_config()?;

    let http = passbolt_sdk::NativeHttpClient::new(&config.http_config()?)?;

    // Build MFA provider from config
    let mfa_provider: Option<Box<dyn passbolt_sdk::MfaProvider>> =
        match sdk_config.mfa_mode.as_str() {
            "none" => None,
            // `noninteractive-totp` is go-passbolt-cli's spelling.
            "non-interactive-totp" | "noninteractive-totp" => {
                Some(Box::new(passbolt_sdk::mfa::TotpProvider::new(
                    &sdk_config.mfa_totp_token,
                    sdk_config.mfa_totp_offset,
                    config.mfa_retry_delay()?,
                )?))
            }
            "interactive-totp" => Some(Box::new(crate::util::mfa::TerminalMfaProvider)),
            other => anyhow::bail!(
                "Unknown MFA mode {other}: use none, interactive-totp or noninteractive-totp"
            ),
        };

    let max_attempts = sdk_config.mfa_retrys.max(1);

    let client =
        passbolt_sdk::PassboltSdk::login(http, &sdk_config, mfa_provider, max_attempts).await?;

    Ok(client)
}
