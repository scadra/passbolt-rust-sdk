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

#[derive(Args, Debug)]
pub struct ConfigureArgs {
    /// Passbolt server address
    #[arg(long, env = "PASSBOLT_SERVER_ADDRESS")]
    pub server_address: Option<String>,

    /// User PGP private key (armored inline)
    #[arg(long)]
    pub user_private_key: Option<String>,

    /// Path to PGP private key file
    #[arg(long, env = "PASSBOLT_USER_PRIVATE_KEY_FILE")]
    pub user_private_key_file: Option<String>,

    /// Master password
    #[arg(long)]
    pub user_password: Option<String>,

    /// MFA mode
    #[arg(long, env = "PASSBOLT_MFA_MODE")]
    pub mfa_mode: Option<String>,

    /// TOTP token
    #[arg(long)]
    pub mfa_totp_token: Option<String>,

    /// TLS skip verify
    #[arg(long, env = "PASSBOLT_TLS_SKIP_VERIFY")]
    pub tls_skip_verify: Option<bool>,

    /// Request timeout
    #[arg(long, env = "PASSBOLT_TIMEOUT")]
    pub timeout: Option<String>,

    /// Number of parallel workers
    #[arg(long, env = "PASSBOLT_WORKERS")]
    pub workers: Option<usize>,

    /// HTTP proxy URL (e.g. `http://localhost:8080`)
    #[arg(long, env = "PASSBOLT_PROXY")]
    pub proxy: Option<String>,

    /// TLS client certificate (PEM, inline)
    #[arg(long, env = "PASSBOLT_TLS_CLIENT_CERT")]
    pub tls_client_cert: Option<String>,

    /// TLS client private key (PEM, inline)
    #[arg(long)]
    pub tls_client_private_key: Option<String>,

    /// Path to TLS client certificate file
    #[arg(long, env = "PASSBOLT_TLS_CLIENT_CERT_FILE")]
    pub tls_client_cert_file: Option<String>,

    /// Path to TLS client private key file
    #[arg(long, env = "PASSBOLT_TLS_CLIENT_PRIVATE_KEY_FILE")]
    pub tls_client_private_key_file: Option<String>,

    /// Number of MFA attempts, at most 3: the server disables the account after too many wrong
    /// codes
    #[arg(long, env = "PASSBOLT_MFA_RETRYS")]
    pub mfa_retrys: Option<u32>,

    /// Minimum delay between MFA attempts (e.g. 10s); a new attempt also waits for a new TOTP
    /// code
    #[arg(long, env = "PASSBOLT_MFA_DELAY")]
    pub mfa_delay: Option<String>,

    /// TOTP time offset in seconds
    #[arg(long, env = "PASSBOLT_MFA_TOTP_OFFSET")]
    pub mfa_totp_offset: Option<i64>,
}

/// Write the settings into the config file, the `PASSBOLT_*` variables included as
/// go-passbolt-cli does, but not the secrets: a password or key exported for one run must not
/// end up on disk. Secrets are saved only when given on the command line.
pub fn run(args: &ConfigureArgs) -> Result<()> {
    let mut config = Config::load()?;
    config.keep_the_secrets_of(&Config::load_file()?);

    if let Some(value) = &args.server_address {
        config.server_address.clone_from(value);
    }
    if let Some(value) = &args.user_private_key {
        config.user_private_key.clone_from(value);
    }
    if let Some(value) = &args.user_private_key_file {
        config.user_private_key_file.clone_from(value);
    }
    if let Some(value) = &args.user_password {
        config.user_password.clone_from(value);
    }
    if let Some(value) = &args.mfa_mode {
        config.mfa_mode.clone_from(value);
    }
    if let Some(value) = &args.mfa_totp_token {
        config.mfa_totp_token.clone_from(value);
    }
    if let Some(value) = args.tls_skip_verify {
        config.tls_skip_verify = value;
    }
    if let Some(value) = &args.timeout {
        config.timeout.clone_from(value);
    }
    if let Some(value) = args.workers {
        config.workers = value;
    }
    if let Some(value) = &args.proxy {
        config.proxy.clone_from(value);
    }
    if let Some(value) = &args.tls_client_cert {
        config.tls_client_cert.clone_from(value);
    }
    if let Some(value) = &args.tls_client_private_key {
        config.tls_client_private_key.clone_from(value);
    }
    if let Some(path) = &args.tls_client_cert_file {
        config.tls_client_cert = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read TLS client cert file: {path}"))?;
    }
    if let Some(path) = &args.tls_client_private_key_file {
        config.tls_client_private_key = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read TLS client private key file: {path}"))?;
    }
    if let Some(value) = args.mfa_retrys {
        config.mfa_retrys = value;
    }
    if let Some(value) = &args.mfa_delay {
        config.mfa_delay.clone_from(value);
    }
    if let Some(value) = args.mfa_totp_offset {
        config.mfa_totp_offset = value;
    }

    config.save()?;

    let path = Config::config_path()?;
    println!("Configuration saved to {}", path.display());

    Ok(())
}
