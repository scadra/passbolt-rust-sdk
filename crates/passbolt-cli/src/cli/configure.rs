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

/// Save the global flags given, with the environment and the config file, to the config file.
/// The secrets of environment variables are not saved: export them again, or give them as
/// flags.
#[derive(Args, Debug)]
pub struct ConfigureArgs {}

pub fn run(_args: &ConfigureArgs, config: &Config) -> Result<()> {
    config.save()?;
    if config.debug {
        println!("Saved: {}", config.masked_settings());
    }
    Ok(())
}
