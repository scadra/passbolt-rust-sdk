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

/// Codes asked in interactive-totp mode, as go-passbolt-cli asks them.
pub const INTERACTIVE_ATTEMPTS: u32 = 3;

/// Asks for each TOTP code: `Enter TOTP:` on stderr, read from the terminal, or from stdin when
/// it is not one.
pub struct TerminalMfaProvider;

impl MfaProvider for TerminalMfaProvider {
    fn get_totp_code(&self) -> Result<String, PassboltError> {
        crate::util::password::prompt_secret("Enter TOTP:")
            .map(|code| code.trim().to_string())
            .map_err(|error| PassboltError::Other(format!("reading TOTP: {error}")))
    }

    fn code_refused(&self) {
        println!("TOTP Verification Failed");
    }
}
