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

use passbolt_sdk::config::SdkConfig;
use passbolt_sdk::error::PassboltError;
use passbolt_sdk::mfa::TotpProvider;

pub const NON_INTERACTIVE_TOTP: &str = "non-interactive-totp";

/// The TOTP provider of the `non-interactive-totp` mode, `None` for any other mode. A retry
/// waits for the next TOTP window: the same code is never sent twice.
pub fn totp_provider(config: &SdkConfig) -> Result<Option<TotpProvider>, PassboltError> {
    if config.mfa_mode != NON_INTERACTIVE_TOTP {
        return Ok(None);
    }
    TotpProvider::new(
        &config.mfa_totp_token,
        config.mfa_totp_offset,
        std::time::Duration::ZERO,
    )
    .map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The login config, non-interactive TOTP with `mfa_totp_token` when it is not empty.
    fn config(mfa_totp_token: &str) -> SdkConfig {
        crate::build_sdk_config(
            "https://passbolt.test".into(),
            "armored key".into(),
            "passphrase".into(),
            crate::FfiLoginOptions {
                mfa_totp_token: Some(mfa_totp_token.into()),
                ..crate::FfiLoginOptions::default()
            },
        )
    }

    #[test]
    fn test_without_a_secret_there_is_no_totp_provider() {
        assert!(totp_provider(&config("")).unwrap().is_none());
    }

    #[test]
    fn test_an_80_bit_secret_gives_a_provider() {
        assert!(totp_provider(&config("JBSWY3DPEHPK3PXP"))
            .unwrap()
            .is_some());
    }

    #[test]
    fn test_a_secret_that_is_not_base32_is_refused_at_login() {
        let error = totp_provider(&config("not base32!")).err().unwrap();

        assert!(error.to_string().contains("base32"), "{error}");
    }
}
