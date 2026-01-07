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
use directories::ProjectDirs;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop};

const APP_QUALIFIER: &str = "";
const APP_ORG: &str = "";
const APP_NAME: &str = "passbolt";

/// Set by `--config` / `PASSBOLT_CONFIG`.
static PATH_OVERRIDE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Full configuration for passbolt-rs.
///
/// Derives `Zeroize`/`ZeroizeOnDrop` so that all fields — including the private
/// key armored text and passphrase — are overwritten in memory when the struct
/// is dropped.  `Debug` is intentionally absent to prevent credentials from
/// leaking through `{:?}` formatting.
#[derive(Clone, Serialize, Deserialize, Default, Zeroize, ZeroizeOnDrop)]
pub struct Config {
    #[serde(default)]
    pub server_address: String,
    #[serde(default)]
    pub user_private_key: String,
    #[serde(default)]
    pub user_private_key_file: String,
    #[serde(default)]
    pub user_password: String,
    /// "interactive-totp", "non-interactive-totp", "none"
    #[serde(default = "default_mfa_mode")]
    pub mfa_mode: String,
    #[serde(default)]
    pub mfa_totp_token: String,
    #[serde(default)]
    pub mfa_totp_offset: i64,
    #[serde(default = "default_mfa_retrys")]
    pub mfa_retrys: u32,
    #[serde(default = "default_mfa_delay")]
    pub mfa_delay: String,
    #[serde(default)]
    pub tls_skip_verify: bool,
    #[serde(default)]
    pub tls_client_cert: String,
    #[serde(default)]
    pub tls_client_private_key: String,
    #[serde(default = "default_timeout")]
    pub timeout: String,
    /// 0 = auto-detect (number of CPUs)
    #[serde(default)]
    pub workers: usize,
    /// Server public key pinned by `passbolt verify`.
    #[serde(default)]
    pub server_public_key: String,
    /// Fingerprint of the shared metadata key pinned by `passbolt verify`.
    #[serde(default)]
    pub metadata_key_fingerprint: String,
    #[serde(default)]
    pub server_verify_token: String,
    #[serde(default)]
    pub server_verify_enc_token: String,
    #[serde(default)]
    pub debug: bool,
    /// HTTP/HTTPS proxy URL (empty = no proxy)
    #[serde(default)]
    pub proxy: String,
    /// `host:port:address` pinning, like `curl --resolve` (empty = DNS)
    #[serde(default)]
    pub resolve: String,
}

/// Parse a duration such as `30s`, `1m` or `2h`.
fn parse_duration(value: &str) -> Result<std::time::Duration> {
    let (amount, unit) = value.split_at(
        value
            .trim_end_matches(|c: char| c.is_ascii_alphabetic())
            .len(),
    );
    let amount: u64 = amount
        .parse()
        .with_context(|| format!("Invalid duration {value:?}, expected e.g. 30s, 1m, 2h"))?;
    let seconds = match unit {
        "s" => amount,
        "m" => amount * 60,
        "h" => amount * 3600,
        _ => anyhow::bail!("Invalid duration {value:?}, expected e.g. 30s, 1m, 2h"),
    };
    Ok(std::time::Duration::from_secs(seconds))
}

/// Parse `host:port:address`, as `curl --resolve` takes it.
fn parse_resolve(value: &str) -> Result<Option<(String, std::net::SocketAddr)>> {
    if value.is_empty() {
        return Ok(None);
    }
    let mut parts = value.splitn(3, ':');
    let (Some(host), Some(port), Some(address)) = (parts.next(), parts.next(), parts.next()) else {
        anyhow::bail!("Invalid --resolve {value:?}, expected host:port:address");
    };
    let port: u16 = port
        .parse()
        .with_context(|| format!("Invalid port in --resolve {value:?}"))?;
    let address: std::net::IpAddr = address
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .with_context(|| format!("Invalid address in --resolve {value:?}"))?;
    Ok(Some((
        host.to_string(),
        std::net::SocketAddr::new(address, port),
    )))
}

fn default_mfa_mode() -> String {
    "interactive-totp".into()
}

const fn default_mfa_retrys() -> u32 {
    3
}

fn default_mfa_delay() -> String {
    "10s".into()
}

fn default_timeout() -> String {
    "1m".into()
}

impl Config {
    /// Read and write the configuration at `path` instead of the default location.
    pub fn set_path(path: PathBuf) {
        let _ = PATH_OVERRIDE.set(path);
    }

    /// Return the configuration file path: `--config`, else the XDG location.
    pub fn config_path() -> Result<PathBuf> {
        if let Some(path) = PATH_OVERRIDE.get() {
            return Ok(path.clone());
        }
        let dirs = ProjectDirs::from(APP_QUALIFIER, APP_ORG, APP_NAME)
            .context("Cannot determine config directory")?;
        Ok(dirs.config_dir().join("config.toml"))
    }

    /// Load the config file (if it exists), then the `PASSBOLT_*` variables over it.
    pub fn load() -> Result<Self> {
        Self::load_from(&Self::config_path()?)
    }

    /// Load the config at `path` (if it exists), then the `PASSBOLT_*` variables over it.
    pub fn load_from(path: &Path) -> Result<Self> {
        Self::read(path, true)
    }

    /// Pin the server public key in the config file, changing nothing else in it:
    /// the command line and environment overrides stay out of the file.
    pub fn save_server_public_key(server_public_key: &str) -> Result<()> {
        let path = Self::config_path()?;
        let mut stored = Self::read(&path, false)?;
        stored.server_public_key = server_public_key.to_string();
        stored.server_verify_token.clear();
        stored.server_verify_enc_token.clear();
        stored.save_to(&path)
    }

    /// Pin the shared metadata key fingerprint in the config file, changing nothing else in it.
    pub fn save_metadata_key_fingerprint(fingerprint: &str) -> Result<()> {
        let path = Self::config_path()?;
        let mut stored = Self::read(&path, false)?;
        stored.metadata_key_fingerprint = fingerprint.to_string();
        stored.save_to(&path)
    }

    fn read(path: &Path, with_environment: bool) -> Result<Self> {
        let mut settings = config::Config::builder();
        if path.exists() {
            settings = settings.add_source(
                config::File::from(path.to_path_buf()).format(config::FileFormat::Toml),
            );
        }
        if with_environment {
            // No separator: `PASSBOLT_SERVER_ADDRESS` is `server_address`, not `server.address`.
            settings = settings.add_source(config::Environment::with_prefix("PASSBOLT"));
        }

        settings
            .build()
            .and_then(config::Config::try_deserialize)
            .with_context(|| format!("Cannot read config file {}", path.display()))
    }

    /// Save the config to its file, readable by its owner only on Unix.
    pub fn save(&self) -> Result<()> {
        self.save_to(&Self::config_path()?)
    }

    /// Save the config to `path`, readable by its owner only on Unix.
    pub fn save_to(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("Cannot create config directory")?;
        }
        let toml_text = toml::to_string_pretty(self).context("Cannot serialize config")?;
        let write_context = || format!("Cannot write config file {}", path.display());

        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)
                .with_context(write_context)?;
            // `mode` only applies when the file is created.
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .with_context(write_context)?;
            file.write_all(toml_text.as_bytes())
                .with_context(write_context)?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(path, toml_text).with_context(write_context)?;
        }

        Ok(())
    }

    /// Build an `SdkConfig` from the CLI config, resolving the private key.
    pub fn to_sdk_config(&self) -> Result<passbolt_sdk::SdkConfig> {
        let private_key_armored = self.private_key_text()?;
        Ok(passbolt_sdk::SdkConfig {
            server_url: self.server_address.clone(),
            private_key_armored,
            passphrase: SecretString::from(self.user_password.clone()),
            mfa_mode: self.mfa_mode.clone(),
            mfa_totp_token: self.mfa_totp_token.clone(),
            mfa_totp_offset: self.mfa_totp_offset,
            mfa_retrys: self.mfa_retrys,
            tls_skip_verify: self.tls_skip_verify,
            tls_client_cert: self.tls_client_cert.clone(),
            tls_client_private_key: self.tls_client_private_key.clone(),
            proxy: self.proxy.clone(),
            server_public_key: self.server_public_key.clone(),
            metadata_key_fingerprint: self.metadata_key_fingerprint.clone(),
            server_verify_enc_token: self.server_verify_enc_token.clone(),
            server_verify_token: self.server_verify_token.clone(),
        })
    }

    /// Wait between two generated TOTP codes: the same window would give the same code.
    pub fn mfa_retry_delay(&self) -> Result<std::time::Duration> {
        parse_duration(&self.mfa_delay)
    }

    /// HTTP transport settings (TLS, mTLS, proxy, name pinning).
    pub fn http_config(&self) -> Result<passbolt_sdk::NativeHttpConfig> {
        let non_empty = |value: &str| (!value.is_empty()).then(|| value.to_string());
        Ok(passbolt_sdk::NativeHttpConfig {
            tls_skip_verify: self.tls_skip_verify,
            client_cert_pem: non_empty(&self.tls_client_cert).map(String::into_bytes),
            client_key_pem: non_empty(&self.tls_client_private_key).map(String::into_bytes),
            proxy_url: non_empty(&self.proxy),
            resolve: parse_resolve(&self.resolve)?.into_iter().collect(),
            timeout: Some(parse_duration(&self.timeout)?),
        })
    }

    /// Resolve the private key text: inline value or file path.
    pub fn private_key_text(&self) -> Result<String> {
        if !self.user_private_key.is_empty() {
            return Ok(self.user_private_key.clone());
        }
        if !self.user_private_key_file.is_empty() {
            return std::fs::read_to_string(&self.user_private_key_file)
                .context("Cannot read private key file");
        }
        anyhow::bail!("No private key configured (--user-private-key or --user-private-key-file)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("30s", 30)]
    #[case("1m", 60)]
    #[case("2h", 7200)]
    fn test_parse_duration(#[case] value: &str, #[case] seconds: u64) {
        assert_eq!(
            parse_duration(value).unwrap(),
            std::time::Duration::from_secs(seconds)
        );
    }

    #[rstest]
    #[case("")]
    #[case("30")]
    #[case("1d")]
    #[case("abc")]
    fn test_parse_duration_rejects(#[case] value: &str) {
        assert!(parse_duration(value).is_err());
    }

    #[test]
    fn test_default_no_panic() {
        // Config::default() is derived via Zeroize, which zeroes all fields.
        // Serde defaults (#[serde(default = "...")]) only apply during deserialization.
        let config = Config::default();
        assert!(!config.tls_skip_verify);
        assert!(!config.debug);
        assert_eq!(config.mfa_retrys, 0); // zeroed
        assert_eq!(config.server_address, "");
    }

    #[test]
    fn test_toml_roundtrip() {
        let mut config = Config::default();
        config.server_address = "https://pass.example.com".into();
        config.user_private_key =
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\nfakekey\n-----END PGP PRIVATE KEY BLOCK-----"
                .into();
        config.user_password = "hunter2".into();
        config.debug = true;
        config.mfa_retrys = 5;

        let toml_str = toml::to_string_pretty(&config).unwrap();
        let loaded: Config = toml::from_str(&toml_str).unwrap();

        assert_eq!(loaded.server_address, "https://pass.example.com");
        assert_eq!(loaded.user_password, "hunter2");
        assert!(loaded.debug);
        assert_eq!(loaded.mfa_retrys, 5);
    }

    #[test]
    fn test_private_key_text_inline() {
        let mut config = Config::default();
        config.user_private_key = "-----BEGIN PGP PRIVATE KEY BLOCK-----".into();
        let text = config.private_key_text().unwrap();
        assert!(text.starts_with("-----BEGIN PGP PRIVATE KEY BLOCK-----"));
    }

    #[test]
    fn test_private_key_text_file() {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "-----BEGIN PGP PRIVATE KEY BLOCK-----").unwrap();
        writeln!(file, "key-from-file").unwrap();

        let mut config = Config::default();
        config.user_private_key_file = file.path().to_string_lossy().into_owned();
        let text = config.private_key_text().unwrap();
        assert!(text.contains("key-from-file"));
    }

    #[test]
    fn test_private_key_text_missing() {
        let config = Config::default();
        assert!(config.private_key_text().is_err());
    }

    #[test]
    fn test_private_key_inline_takes_priority() {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "from-file").unwrap();

        let mut config = Config::default();
        config.user_private_key = "inline-key".into();
        config.user_private_key_file = file.path().to_string_lossy().into_owned();

        let text = config.private_key_text().unwrap();
        assert_eq!(text, "inline-key");
    }

    #[cfg(unix)]
    #[test]
    fn test_save_restricts_an_existing_file_to_its_owner() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        Config::default().save_to(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn test_save_creates_a_file_readable_by_its_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("nested/config.toml");

        Config::default().save_to(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn test_save_then_load_keeps_the_settings() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        let mut config = Config::default();
        config.server_address = "https://pass.example.com".into();
        config.mfa_retrys = 5;

        config.save_to(&path).unwrap();
        let loaded = Config::load_from(&path).unwrap();

        assert_eq!(loaded.server_address, "https://pass.example.com");
        assert_eq!(loaded.mfa_retrys, 5);
    }

    #[test]
    fn test_load_without_a_file_gives_the_defaults() {
        let directory = tempfile::tempdir().unwrap();

        let config = Config::load_from(&directory.path().join("absent.toml")).unwrap();

        assert_eq!(config.mfa_mode, "interactive-totp");
        assert_eq!(config.mfa_retrys, 3);
        assert_eq!(config.mfa_delay, "10s");
        assert_eq!(config.timeout, "1m");
    }

    #[test]
    fn test_load_fills_missing_settings_with_the_defaults() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        std::fs::write(&path, "mfa_mode = \"none\"\n").unwrap();

        let config = Config::load_from(&path).unwrap();

        assert_eq!(config.mfa_mode, "none");
        assert_eq!(config.mfa_retrys, 3);
    }

    #[test]
    fn test_load_reports_the_path_of_an_invalid_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        std::fs::write(&path, "server_address = [not toml").unwrap();

        let error = Config::load_from(&path).err().unwrap();

        assert!(
            error.to_string().contains(&path.display().to_string()),
            "{error}"
        );
    }

    #[rstest::rstest]
    #[case("host:443:1.2.3.4", "host", "1.2.3.4:443")]
    #[case("host:443:[::1]", "host", "[::1]:443")]
    #[case("host:443:::1", "host", "[::1]:443")]
    fn test_parse_resolve_accepts(
        #[case] value: &str,
        #[case] expected_host: &str,
        #[case] expected_address: &str,
    ) {
        let (host, address) = parse_resolve(value).unwrap().unwrap();

        assert_eq!(host, expected_host);
        assert_eq!(address, expected_address.parse().unwrap());
    }

    #[rstest::rstest]
    #[case::missing_port("host")]
    #[case::missing_address("host:443")]
    #[case::port_out_of_range("host:65536:1.2.3.4")]
    #[case::address_not_an_ip("host:443:example.com")]
    fn test_parse_resolve_rejects(#[case] value: &str) {
        let error = parse_resolve(value).err().unwrap();

        assert!(error.to_string().contains("--resolve"), "{error}");
    }

    #[test]
    fn test_parse_resolve_empty_is_none() {
        assert!(parse_resolve("").unwrap().is_none());
    }
}
