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

use passbolt_sdk::error::PassboltError;
use passbolt_sdk::MfaProvider;

/// Interactive MFA: prompts the user via terminal.
pub struct TerminalMfaProvider;

impl MfaProvider for TerminalMfaProvider {
    fn get_totp_code(&self) -> Result<String, PassboltError> {
        rpassword::prompt_password("TOTP code: ")
            .map_err(|error| PassboltError::Other(format!("Failed to read TOTP code: {error}")))
    }
}
