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

//! Settings, from the lowest precedence to the highest: the defaults, the config file, the
//! go-passbolt-cli environment variables (`SERVERADDRESS`, `MFAMODE`…), the `PASSBOLT_*`
//! variables, then the command-line flags.
//!
//! The config file is ours (`<config dir>/passbolt/config.toml`) or, when it does not exist,
//! go-passbolt-cli's (`<config dir>/go-passbolt-cli/go-passbolt-cli.{json,toml,yaml,yml}`).
//! Keys are read whatever their case and underscores: `server_address`, `serverAddress` and
//! `serveraddress` are the same setting.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use directories::{BaseDirs, ProjectDirs};
use secrecy::SecretString;
use zeroize::{Zeroize, ZeroizeOnDrop};

const APP_QUALIFIER: &str = "";
const APP_ORG: &str = "";
const APP_NAME: &str = "passbolt";
const GO_APP_NAME: &str = "go-passbolt-cli";
/// The extensions viper looks for, in its order.
const GO_EXTENSIONS: [&str; 4] = ["json", "toml", "yaml", "yml"];

/// Set by `--config` / `PASSBOLT_CONFIG`.
static PATH_OVERRIDE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Where a setting comes from, from the lowest precedence to the highest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Origin {
    Default,
    File,
    /// go-passbolt-cli's variables, without prefix (viper's `AutomaticEnv`).
    GoEnvironment,
    /// `PASSBOLT_*`.
    Environment,
    Flag,
}

impl Origin {
    const fn is_environment(self) -> bool {
        matches!(self, Self::GoEnvironment | Self::Environment)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Text,
    /// Never saved from the environment.
    Secret,
    Bool,
    Count,
    Duration,
    /// A duration that may be negative.
    SignedDuration,
    /// A path whose content goes to the setting named.
    FileOf(&'static str),
    /// go-passbolt-cli's deprecated spelling, used when the setting named is empty.
    LegacyOf(&'static str),
}

struct Setting {
    name: &'static str,
    go_name: &'static str,
    kind: Kind,
    /// Read from the variable named after `go_name`, in capitals, as go-passbolt-cli does.
    go_environment: bool,
}

const fn setting(
    name: &'static str,
    go_name: &'static str,
    kind: Kind,
    go_environment: bool,
) -> Setting {
    Setting {
        name,
        go_name,
        kind,
        go_environment,
    }
}

const SETTINGS: &[Setting] = &[
    setting("server_address", "serverAddress", Kind::Text, true),
    setting("user_private_key", "userPrivateKey", Kind::Secret, true),
    setting(
        "user_private_key_file",
        "userPrivateKeyFile",
        Kind::FileOf("user_private_key"),
        false,
    ),
    setting("user_password", "userPassword", Kind::Secret, true),
    setting("mfa_mode", "mfaMode", Kind::Text, true),
    setting("mfa_totp_token", "mfaTotpToken", Kind::Secret, true),
    setting(
        "totp_token",
        "totpToken",
        Kind::LegacyOf("mfa_totp_token"),
        true,
    ),
    setting(
        "mfa_totp_offset",
        "mfaTotpOffset",
        Kind::SignedDuration,
        true,
    ),
    setting(
        "totp_offset",
        "totpOffset",
        Kind::LegacyOf("mfa_totp_offset"),
        true,
    ),
    setting("mfa_retrys", "mfaRetrys", Kind::Count, true),
    setting("mfa_delay", "mfaDelay", Kind::Duration, true),
    setting("tls_skip_verify", "tlsSkipVerify", Kind::Bool, true),
    setting("tls_client_cert", "tlsClientCert", Kind::Text, true),
    setting(
        "tls_client_private_key",
        "tlsClientPrivateKey",
        Kind::Secret,
        true,
    ),
    setting(
        "tls_client_cert_file",
        "tlsClientCertFile",
        Kind::FileOf("tls_client_cert"),
        false,
    ),
    setting(
        "tls_client_private_key_file",
        "tlsClientPrivateKeyFile",
        Kind::FileOf("tls_client_private_key"),
        false,
    ),
    setting("timeout", "timeout", Kind::Duration, true),
    setting("workers", "workers", Kind::Count, true),
    setting("debug", "debug", Kind::Bool, true),
    setting("server_verify_token", "serverVerifyToken", Kind::Text, true),
    setting(
        "server_verify_enc_token",
        "serverVerifyEncToken",
        Kind::Text,
        true,
    ),
    setting("server_public_key", "serverPublicKey", Kind::Text, false),
    setting(
        "metadata_key_fingerprint",
        "metadataKeyFingerprint",
        Kind::Text,
        false,
    ),
    setting("proxy", "proxy", Kind::Text, false),
    setting("resolve", "resolve", Kind::Text, false),
];

/// `serverAddress`, `server_address`, `server-address` and `SERVERADDRESS` are one key.
fn canonical(key: &str) -> String {
    key.chars()
        .filter(|character| !matches!(character, '_' | '-'))
        .flat_map(char::to_lowercase)
        .collect()
}

fn find_setting(key: &str) -> Option<&'static Setting> {
    let key = canonical(key);
    SETTINGS
        .iter()
        .find(|setting| canonical(setting.name) == key)
}

/// A boolean as Go's `strconv.ParseBool` reads it.
pub fn parse_go_bool(text: &str) -> Result<bool, String> {
    match text {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Ok(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Ok(false),
        _ => Err(format!("invalid boolean {text:?}: use true or false")),
    }
}

/// A duration with Go's grammar (`1m30s`, `-1h`); a plain number is seconds, as this CLI
/// took them before.
pub fn parse_duration(text: &str) -> Result<chrono::TimeDelta> {
    if let Ok(seconds) = text.trim().parse::<i64>() {
        return chrono::TimeDelta::try_seconds(seconds)
            .with_context(|| format!("Invalid duration {text:?}"));
    }
    passbolt_sdk::parse_go_duration(text.trim()).map_err(|error| anyhow::anyhow!("{error}"))
}

fn std_duration(duration: chrono::TimeDelta) -> std::time::Duration {
    duration.to_std().unwrap_or_default()
}

/// The value written in the config file, normalized: `1m` is `1m0s`, as go-passbolt-cli
/// writes it.
fn normalize(setting: &Setting, text: &str) -> Result<String> {
    match setting.kind {
        Kind::Text | Kind::Secret | Kind::FileOf(_) => Ok(text.to_string()),
        Kind::Bool => parse_go_bool(text.trim())
            .map(|value| value.to_string())
            .map_err(anyhow::Error::msg),
        Kind::Count => text
            .trim()
            .parse::<u32>()
            .map(|value| value.to_string())
            .with_context(|| format!("invalid number {text:?}")),
        Kind::Duration | Kind::SignedDuration => {
            let duration = parse_duration(text)?;
            if setting.kind == Kind::Duration && duration < chrono::TimeDelta::zero() {
                anyhow::bail!("negative duration {text:?}");
            }
            Ok(passbolt_sdk::format_go_duration(duration))
        }
        Kind::LegacyOf(target) => find_setting(target)
            .map_or_else(|| Ok(text.to_string()), |target| normalize(target, text)),
    }
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

/// The settings one source gives, by setting name.
type Layer = Vec<(&'static Setting, String)>;

/// Full configuration for passbolt-rs.
///
/// Derives `Zeroize`/`ZeroizeOnDrop` so that all fields — including the private
/// key armored text and passphrase — are overwritten in memory when the struct
/// is dropped.  `Debug` is intentionally absent to prevent credentials from
/// leaking through `{:?}` formatting.
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct Config {
    pub server_address: String,
    /// The armored key: `--userPrivateKeyFile` puts the content of its file here.
    pub user_private_key: String,
    pub user_password: String,
    /// "interactive-totp", "noninteractive-totp" (or "non-interactive-totp"), "none"; any
    /// other mode is "none", as for go-passbolt-cli.
    pub mfa_mode: String,
    pub mfa_totp_token: String,
    /// Go duration, such as `30s` or `-1m0s`.
    pub mfa_totp_offset: String,
    pub mfa_retrys: u32,
    /// Go duration.
    pub mfa_delay: String,
    pub tls_skip_verify: bool,
    pub tls_client_cert: String,
    pub tls_client_private_key: String,
    /// Go duration: each request and the whole command must end within it.
    pub timeout: String,
    /// 0 = auto-detect (number of CPUs)
    pub workers: usize,
    /// Server public key pinned by `passbolt verify`.
    pub server_public_key: String,
    /// Fingerprint of the shared metadata key pinned by `passbolt verify`.
    pub metadata_key_fingerprint: String,
    pub server_verify_token: String,
    pub server_verify_enc_token: String,
    pub debug: bool,
    /// HTTP/HTTPS proxy URL (empty = no proxy)
    pub proxy: String,
    /// `host:port:address` pinning, like `curl --resolve` (empty = DNS)
    pub resolve: String,
    #[zeroize(skip)]
    origins: BTreeMap<&'static str, Origin>,
    /// The config file read, if any.
    #[zeroize(skip)]
    file: Option<PathBuf>,
    /// The file read uses go-passbolt-cli's keys (`serveraddress`): saved with them.
    #[zeroize(skip)]
    go_keys: bool,
}

/// What a config file holds, by setting name; keys it does not know are left out.
struct FileSettings {
    values: Vec<(&'static Setting, String)>,
    go_keys: bool,
}

impl Config {
    /// Read and write the configuration at `path` instead of the default location.
    pub fn set_path(path: PathBuf) {
        let _ = PATH_OVERRIDE.set(path);
    }

    /// Our config file: `<config dir>/passbolt/config.toml`.
    fn default_path() -> Result<PathBuf> {
        let dirs = ProjectDirs::from(APP_QUALIFIER, APP_ORG, APP_NAME)
            .context("Cannot determine config directory")?;
        Ok(dirs.config_dir().join("config.toml"))
    }

    /// go-passbolt-cli's config files, in the order viper looks for them.
    fn go_paths() -> Vec<PathBuf> {
        BaseDirs::new()
            .map(|dirs| {
                let directory = dirs.config_dir().join(GO_APP_NAME);
                GO_EXTENSIONS
                    .iter()
                    .map(|extension| directory.join(format!("{GO_APP_NAME}.{extension}")))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The config file to read: `--config`, else ours if it exists, else go-passbolt-cli's.
    fn path_to_read() -> Option<PathBuf> {
        if let Some(path) = PATH_OVERRIDE.get() {
            return Some(path.clone());
        }
        if let Ok(path) = Self::default_path() {
            if path.exists() {
                return Some(path);
            }
        }
        Self::go_paths().into_iter().find(|path| path.exists())
    }

    /// The file `save` writes: the one read, else `--config`, else ours.
    pub fn save_path(&self) -> Result<PathBuf> {
        if let Some(path) = PATH_OVERRIDE.get() {
            return Ok(path.clone());
        }
        self.file
            .as_ref()
            .map_or_else(Self::default_path, |path| Ok(path.clone()))
    }

    /// Load the config file and the environment, then `flags` (setting name, value) over them.
    pub fn load_with(flags: &[(&str, String)]) -> Result<Self> {
        let path = Self::path_to_read();
        Self::load_layers(path.as_deref(), &environment_layers(), flags)
    }

    fn load_layers(
        path: Option<&Path>,
        environment: &[(Origin, Layer)],
        flags: &[(&str, String)],
    ) -> Result<Self> {
        let mut chosen: BTreeMap<&'static str, (String, Origin)> = BTreeMap::new();
        for (name, value) in [
            ("mfa_mode", "interactive-totp"),
            ("mfa_retrys", "3"),
            ("mfa_delay", "10s"),
            ("timeout", "1m0s"),
            ("mfa_totp_offset", "0s"),
            ("workers", "0"),
        ] {
            chosen.insert(name, (value.to_string(), Origin::Default));
        }

        let file_settings = match path {
            Some(path) if path.exists() => Some(read_file(path)?),
            _ => None,
        };
        if let Some(settings) = &file_settings {
            for (setting, value) in &settings.values {
                let value = normalize(setting, value)
                    .with_context(|| format!("Invalid {} in config file", setting.name))?;
                chosen.insert(setting.name, (value, Origin::File));
            }
        }
        for (origin, layer) in environment {
            for (setting, value) in layer {
                match normalize(setting, value) {
                    Ok(value) => {
                        chosen.insert(setting.name, (value, *origin));
                    }
                    // viper reads an invalid value as the zero value: `DEBUG=*` is not an error.
                    Err(_) if *origin == Origin::GoEnvironment => {}
                    Err(error) => {
                        return Err(error
                            .context(format!("Invalid PASSBOLT_{}", setting.name.to_uppercase())))
                    }
                }
            }
        }
        for (name, value) in flags {
            let setting = find_setting(name).with_context(|| format!("Unknown setting {name}"))?;
            let value = normalize(setting, value)
                .with_context(|| format!("Invalid --{}", setting.go_name))?;
            chosen.insert(setting.name, (value, Origin::Flag));
        }

        let mut config = Self::default();
        config.file = path
            .filter(|_| file_settings.is_some())
            .map(Path::to_path_buf);
        config.go_keys = file_settings
            .as_ref()
            .is_some_and(|settings| settings.go_keys);
        config.resolve(chosen)?;
        if let (true, Some(path)) = (config.debug, &config.file) {
            eprintln!("Using config file: {}", path.display());
        }
        Ok(config)
    }

    fn resolve(&mut self, mut chosen: BTreeMap<&'static str, (String, Origin)>) -> Result<()> {
        let debug = chosen
            .get("debug")
            .is_some_and(|(value, _)| value == "true");
        for setting in SETTINGS {
            let Some((value, origin)) = chosen.remove(setting.name) else {
                continue;
            };
            match setting.kind {
                Kind::LegacyOf(target) => {
                    let current = chosen.get(target).map(|(value, _)| value.as_str());
                    if matches!(current, None | Some("" | "0s")) {
                        chosen.insert(target, (value, origin));
                    }
                }
                Kind::FileOf(target) => {
                    if value.is_empty() {
                        continue;
                    }
                    let inline_origin = chosen.get(target).map(|(_, origin)| *origin);
                    if inline_origin.is_some_and(|inline| inline > origin) {
                        continue;
                    }
                    if debug {
                        eprintln!("Loading file: {value}");
                    }
                    let content = std::fs::read_to_string(&value).with_context(|| {
                        format!("Cannot read {}: {value}", file_description(setting.name))
                    })?;
                    chosen.insert(target, (content, origin));
                }
                _ => {
                    chosen.insert(setting.name, (value, origin));
                }
            }
        }
        for (name, (value, origin)) in chosen {
            self.set(name, value)?;
            self.origins.insert(name, origin);
        }
        Ok(())
    }

    /// Set a normalized value.
    fn set(&mut self, name: &str, value: String) -> Result<()> {
        let flag = || value == "true";
        let count = || -> Result<u32> { Ok(value.parse()?) };
        match name {
            "server_address" => self.server_address = value,
            "user_private_key" => self.user_private_key = value,
            "user_password" => self.user_password = value,
            "mfa_mode" => self.mfa_mode = value,
            "mfa_totp_token" => self.mfa_totp_token = value,
            "mfa_totp_offset" => self.mfa_totp_offset = value,
            "mfa_retrys" => self.mfa_retrys = count()?,
            "mfa_delay" => self.mfa_delay = value,
            "tls_skip_verify" => self.tls_skip_verify = flag(),
            "tls_client_cert" => self.tls_client_cert = value,
            "tls_client_private_key" => self.tls_client_private_key = value,
            "timeout" => self.timeout = value,
            "workers" => self.workers = usize::try_from(count()?)?,
            "debug" => self.debug = flag(),
            "server_verify_token" => self.server_verify_token = value,
            "server_verify_enc_token" => self.server_verify_enc_token = value,
            "server_public_key" => self.server_public_key = value,
            "metadata_key_fingerprint" => self.metadata_key_fingerprint = value,
            "proxy" => self.proxy = value,
            "resolve" => self.resolve = value,
            _ => {}
        }
        Ok(())
    }

    /// The value saved for `name`.
    fn saved_value(&self, name: &str) -> Option<toml::Value> {
        let text = |value: &str| Some(toml::Value::String(value.to_string()));
        match name {
            "server_address" => text(&self.server_address),
            "user_private_key" => text(&self.user_private_key),
            "user_password" => text(&self.user_password),
            "mfa_mode" => text(&self.mfa_mode),
            "mfa_totp_token" => text(&self.mfa_totp_token),
            "mfa_totp_offset" => text(&self.mfa_totp_offset),
            "mfa_retrys" => Some(toml::Value::Integer(self.mfa_retrys.into())),
            "mfa_delay" => text(&self.mfa_delay),
            "tls_skip_verify" => Some(toml::Value::Boolean(self.tls_skip_verify)),
            "tls_client_cert" => text(&self.tls_client_cert),
            "tls_client_private_key" => text(&self.tls_client_private_key),
            "timeout" => text(&self.timeout),
            "workers" => Some(toml::Value::Integer(
                i64::try_from(self.workers).unwrap_or(0),
            )),
            "debug" => Some(toml::Value::Boolean(self.debug)),
            "server_verify_token" => text(&self.server_verify_token),
            "server_verify_enc_token" => text(&self.server_verify_enc_token),
            "server_public_key" => text(&self.server_public_key),
            "metadata_key_fingerprint" => text(&self.metadata_key_fingerprint),
            "proxy" => text(&self.proxy),
            "resolve" => text(&self.resolve),
            _ => None,
        }
    }

    /// Where `name` came from.
    pub fn origin(&self, name: &str) -> Origin {
        self.origins.get(name).copied().unwrap_or(Origin::Default)
    }

    /// The settings `save` writes, by key: the secrets set by the environment are left as the
    /// file had them, so that a variable exported for one run does not end up on disk.
    fn saved_settings(&self, stored: &[(&'static Setting, String)]) -> Vec<(String, toml::Value)> {
        SETTINGS
            .iter()
            .filter_map(|setting| {
                let value =
                    if setting.kind == Kind::Secret && self.origin(setting.name).is_environment() {
                        let kept = stored
                            .iter()
                            .find(|(stored_setting, _)| stored_setting.name == setting.name)
                            .map(|(_, value)| value.clone())
                            .unwrap_or_default();
                        toml::Value::String(kept)
                    } else {
                        self.saved_value(setting.name)?
                    };
                let key = if self.go_keys {
                    setting.go_name.to_lowercase()
                } else {
                    setting.name.to_string()
                };
                Some((key, value))
            })
            .collect()
    }

    /// The settings `save` writes, secrets masked, for `--debug`.
    pub fn masked_settings(&self) -> String {
        let settings = self.saved_settings(&[]);
        let shown: Vec<String> = settings
            .into_iter()
            .map(|(key, value)| {
                let secret = find_setting(&key).is_some_and(|setting| setting.kind == Kind::Secret);
                match value {
                    toml::Value::String(text) if secret && !text.is_empty() => {
                        format!("{key}:********")
                    }
                    toml::Value::String(text) => format!("{key}:{}", one_line(&text)),
                    other => format!("{key}:{other}"),
                }
            })
            .collect();
        format!("map[{}]", shown.join(" "))
    }

    /// Save the effective settings to the config file (see [`Self::save_path`]), in the format
    /// of its extension, readable by its owner only on Unix.
    pub fn save(&self) -> Result<()> {
        let path = self.save_path()?;
        let stored = if path.exists() {
            read_file(&path)?.values
        } else {
            Vec::new()
        };
        let mut config = self.clone();
        config.go_keys = self.go_keys || !is_toml(&path);
        let settings = config.saved_settings(&stored);
        write_file(&path, &render(&path, settings)?)
    }

    /// Build an `SdkConfig` from the CLI config.
    pub fn to_sdk_config(&self) -> Result<passbolt_sdk::SdkConfig> {
        Ok(passbolt_sdk::SdkConfig {
            server_url: self.server_address.clone(),
            private_key_armored: self.private_key_text()?,
            passphrase: SecretString::from(self.user_password.clone()),
            mfa_mode: self.mfa_mode.clone(),
            mfa_totp_token: self.mfa_totp_token.clone(),
            mfa_totp_offset: self.mfa_totp_offset_seconds()?,
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

    /// The TOTP clock offset, in whole seconds.
    pub fn mfa_totp_offset_seconds(&self) -> Result<i64> {
        Ok(parse_duration(or_zero(&self.mfa_totp_offset))?.num_seconds())
    }

    /// Wait between two generated TOTP codes: the same window would give the same code.
    pub fn mfa_retry_delay(&self) -> Result<std::time::Duration> {
        Ok(std_duration(parse_duration(or_zero(&self.mfa_delay))?))
    }

    /// The time each request, and the whole command, may take; `None` for no limit (0).
    pub fn timeout_duration(&self) -> Result<Option<std::time::Duration>> {
        let timeout = std_duration(parse_duration(or_zero(&self.timeout))?);
        Ok((!timeout.is_zero()).then_some(timeout))
    }

    /// The number of workers: the one asked, else the number of CPUs.
    pub fn worker_count(&self) -> usize {
        if self.workers != 0 {
            return self.workers;
        }
        let count = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        if self.debug {
            eprintln!("Autodetected Worker Count: {count}");
        }
        count
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
            timeout: self.timeout_duration()?,
        })
    }

    /// The armored private key, as go-passbolt-cli asks for it.
    pub fn private_key_text(&self) -> Result<String> {
        if self.user_private_key.is_empty() {
            anyhow::bail!("userPrivateKey is not defined");
        }
        Ok(self.user_private_key.clone())
    }
}

const fn or_zero(text: &str) -> &str {
    if text.is_empty() {
        "0s"
    } else {
        text
    }
}

fn one_line(text: &str) -> String {
    if text.contains('\n') {
        format!("{}…", text.lines().next().unwrap_or_default())
    } else {
        text.to_string()
    }
}

fn file_description(name: &str) -> &'static str {
    match name {
        "tls_client_cert_file" => "TLS client cert file",
        "tls_client_private_key_file" => "TLS client private key file",
        _ => "private key file",
    }
}

/// The variables of both spellings: go-passbolt-cli's (`SERVERADDRESS`) then ours
/// (`PASSBOLT_SERVER_ADDRESS`), which wins. An empty variable is unset, as for viper.
fn environment_layers() -> Vec<(Origin, Layer)> {
    let read = |name: String| std::env::var(name).ok().filter(|value| !value.is_empty());
    let go_layer = SETTINGS
        .iter()
        .filter(|setting| setting.go_environment)
        .filter_map(|setting| Some((setting, read(setting.go_name.to_uppercase())?)))
        .collect();
    let passbolt_layer = SETTINGS
        .iter()
        .filter(|setting| !matches!(setting.kind, Kind::LegacyOf(_)))
        .filter_map(|setting| {
            Some((
                setting,
                read(format!("PASSBOLT_{}", setting.name.to_uppercase()))?,
            ))
        })
        .collect();
    vec![
        (Origin::GoEnvironment, go_layer),
        (Origin::Environment, passbolt_layer),
    ]
}

fn is_toml(path: &Path) -> bool {
    file_format(path) == config::FileFormat::Toml
}

fn file_format(path: &Path) -> config::FileFormat {
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("json") => config::FileFormat::Json,
        Some("yaml" | "yml") => config::FileFormat::Yaml,
        _ => config::FileFormat::Toml,
    }
}

/// Read a config file of any format, restricting it to its owner as go-passbolt-cli does.
fn read_file(path: &Path) -> Result<FileSettings> {
    let context = || format!("Cannot read config file {}", path.display());
    let table = config::Config::builder()
        .add_source(config::File::from(path.to_path_buf()).format(file_format(path)))
        .build()
        .and_then(
            config::Config::try_deserialize::<std::collections::HashMap<String, config::Value>>,
        )
        .with_context(context)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(error) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
            eprintln!("Warning: failed to set config file permissions: {error}");
        }
    }
    let mut values = Vec::new();
    let mut go_keys = false;
    for (key, value) in table {
        let Some(setting) = find_setting(&key) else {
            continue;
        };
        go_keys |= setting.name.contains('_') && !key.contains('_');
        let text = match value.kind {
            config::ValueKind::Nil => String::new(),
            _ => value
                .into_string()
                .with_context(|| format!("Invalid {key} in config file"))
                .with_context(context)?,
        };
        values.push((setting, text));
    }
    Ok(FileSettings { values, go_keys })
}

fn render(path: &Path, settings: Vec<(String, toml::Value)>) -> Result<String> {
    let json = |value: &toml::Value| match value {
        toml::Value::String(text) => serde_json::Value::from(text.as_str()),
        toml::Value::Integer(number) => serde_json::Value::from(*number),
        toml::Value::Boolean(flag) => serde_json::Value::from(*flag),
        other => serde_json::Value::from(other.to_string()),
    };
    match file_format(path) {
        config::FileFormat::Json => {
            let map: serde_json::Map<String, serde_json::Value> = settings
                .iter()
                .map(|(key, value)| (key.clone(), json(value)))
                .collect();
            Ok(serde_json::to_string_pretty(&map).context("Cannot serialize config")? + "\n")
        }
        // A JSON scalar is a YAML scalar.
        config::FileFormat::Yaml => {
            Ok(settings
                .iter()
                .fold(String::new(), |mut text, (key, value)| {
                    let _ = writeln!(text, "{key}: {}", json(value));
                    text
                }))
        }
        _ => toml::to_string_pretty(&settings.into_iter().collect::<toml::Table>())
            .context("Cannot serialize config"),
    }
}

/// Write `text` to `path`, readable by its owner only on Unix, in a directory only they can
/// open when it is created.
fn write_file(path: &Path, text: &str) -> Result<()> {
    let write_context = || format!("Cannot write config file {}", path.display());
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder
            .create(parent)
            .context("Cannot create config directory")?;
    }

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
        file.write_all(text.as_bytes())
            .with_context(write_context)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, text).with_context(write_context)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn layer(origin: Origin, entries: &[(&str, &str)]) -> (Origin, Layer) {
        (
            origin,
            entries
                .iter()
                .map(|(key, value)| (find_setting(key).unwrap(), (*value).to_string()))
                .collect(),
        )
    }

    fn file_with(name: &str, content: &str) -> (tempfile::TempDir, PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(name);
        std::fs::write(&path, content).unwrap();
        (directory, path)
    }

    fn load(
        path: Option<&Path>,
        environment: &[(Origin, Layer)],
        flags: &[(&str, &str)],
    ) -> Result<Config> {
        let flags: Vec<(&str, String)> = flags
            .iter()
            .map(|(name, value)| (*name, (*value).to_string()))
            .collect();
        Config::load_layers(path, environment, &flags)
    }

    #[rstest]
    #[case("30s", 30)]
    #[case("1m", 60)]
    #[case("1m0s", 60)]
    #[case("2h", 7200)]
    #[case("30", 30)]
    #[case("-1m", -60)]
    fn test_parse_duration(#[case] value: &str, #[case] seconds: i64) {
        assert_eq!(parse_duration(value).unwrap().num_seconds(), seconds);
    }

    #[rstest]
    #[case("")]
    #[case("1d")]
    #[case("abc")]
    fn test_parse_duration_rejects(#[case] value: &str) {
        assert!(parse_duration(value).is_err());
    }

    #[rstest]
    #[case("true", true)]
    #[case("1", true)]
    #[case("T", true)]
    #[case("False", false)]
    #[case("0", false)]
    fn test_parse_go_bool(#[case] text: &str, #[case] expected: bool) {
        assert_eq!(parse_go_bool(text).unwrap(), expected);
    }

    #[rstest]
    #[case("yes")]
    #[case("")]
    #[case("*")]
    fn test_parse_go_bool_rejects(#[case] text: &str) {
        assert!(parse_go_bool(text).is_err());
    }

    #[rstest]
    #[case("serverAddress", "server_address")]
    #[case("serveraddress", "server_address")]
    #[case("SERVERADDRESS", "server_address")]
    #[case("server-address", "server_address")]
    #[case("mfaretrys", "mfa_retrys")]
    #[case("tlsClientPrivateKey", "tls_client_private_key")]
    fn test_find_setting_ignores_case_and_separators(#[case] key: &str, #[case] name: &str) {
        assert_eq!(find_setting(key).unwrap().name, name);
    }

    #[test]
    fn test_default_no_panic() {
        // Config::default() is derived, which zeroes all fields: the defaults come with load.
        let config = Config::default();
        assert!(!config.tls_skip_verify);
        assert!(!config.debug);
        assert_eq!(config.mfa_retrys, 0);
        assert_eq!(config.server_address, "");
    }

    #[test]
    fn test_load_without_a_file_gives_the_defaults() {
        let config = load(None, &[], &[]).unwrap();

        assert_eq!(config.mfa_mode, "interactive-totp");
        assert_eq!(config.mfa_retrys, 3);
        assert_eq!(config.mfa_delay, "10s");
        assert_eq!(config.timeout, "1m0s");
        assert_eq!(config.workers, 0);
    }

    #[test]
    fn test_load_fills_missing_settings_with_the_defaults() {
        let (_directory, path) = file_with("config.toml", "mfa_mode = \"none\"\n");

        let config = load(Some(&path), &[], &[]).unwrap();

        assert_eq!(config.mfa_mode, "none");
        assert_eq!(config.mfa_retrys, 3);
    }

    #[test]
    fn test_load_reads_a_file_written_by_go_passbolt_cli() {
        let (_directory, path) = file_with(
            "go-passbolt-cli.toml",
            "serveraddress = 'https://go.example.com'\nmfamode = 'noninteractive-totp'\n\
             mfaretrys = '2'\nmfadelay = '1m0s'\nmfatotpoffset = '-30s'\ntimeout = '0s'\n\
             tlsskipverify = 'true'\nworkers = 4\ndebug = false\nuserpassword = 'secret'\n",
        );

        let config = load(Some(&path), &[], &[]).unwrap();

        assert_eq!(config.server_address, "https://go.example.com");
        assert_eq!(config.mfa_mode, "noninteractive-totp");
        assert_eq!(config.mfa_retrys, 2);
        assert_eq!(config.mfa_retry_delay().unwrap().as_secs(), 60);
        assert_eq!(config.mfa_totp_offset_seconds().unwrap(), -30);
        assert_eq!(config.timeout_duration().unwrap(), None);
        assert!(config.tls_skip_verify);
        assert_eq!(config.workers, 4);
        assert_eq!(config.user_password, "secret");
    }

    #[rstest]
    #[case::json(
        "config.json",
        "{\"serverAddress\": \"https://json.test\", \"mfaretrys\": 2}"
    )]
    #[case::yaml("config.yaml", "serveraddress: https://json.test\nmfaretrys: \"2\"\n")]
    fn test_load_reads_the_format_of_the_extension(#[case] name: &str, #[case] content: &str) {
        let (_directory, path) = file_with(name, content);

        let config = load(Some(&path), &[], &[]).unwrap();

        assert_eq!(config.server_address, "https://json.test");
        assert_eq!(config.mfa_retrys, 2);
    }

    #[test]
    fn test_load_reads_our_integer_offset_as_seconds() {
        let (_directory, path) = file_with("config.toml", "mfa_totp_offset = 5\n");

        let config = load(Some(&path), &[], &[]).unwrap();

        assert_eq!(config.mfa_totp_offset_seconds().unwrap(), 5);
    }

    #[test]
    fn test_load_reports_the_path_of_an_invalid_file() {
        let (_directory, path) = file_with("config.toml", "server_address = [not toml");

        let error = load(Some(&path), &[], &[]).err().unwrap();

        assert!(
            format!("{error:#}").contains(&path.display().to_string()),
            "{error:#}"
        );
    }

    #[test]
    fn test_precedence_is_flag_then_our_variables_then_go_variables_then_file() {
        let (_directory, path) = file_with(
            "config.toml",
            "server_address = 'https://file'\nproxy = 'http://file'\nmfa_mode = 'none'\n\
             timeout = '5s'\n",
        );
        let environment = [
            layer(
                Origin::GoEnvironment,
                &[
                    ("server_address", "https://go"),
                    ("mfa_mode", "interactive-totp"),
                    ("timeout", "6s"),
                ],
            ),
            layer(
                Origin::Environment,
                &[("server_address", "https://ours"), ("timeout", "7s")],
            ),
        ];

        let config = load(Some(&path), &environment, &[("timeout", "8s")]).unwrap();

        assert_eq!(config.proxy, "http://file");
        assert_eq!(config.mfa_mode, "interactive-totp");
        assert_eq!(config.server_address, "https://ours");
        assert_eq!(config.timeout, "8s");
        assert_eq!(config.origin("timeout"), Origin::Flag);
        assert_eq!(config.origin("server_address"), Origin::Environment);
    }

    #[test]
    fn test_an_invalid_go_variable_is_ignored() {
        let environment = [layer(
            Origin::GoEnvironment,
            &[("debug", "*"), ("timeout", "soon")],
        )];

        let config = load(None, &environment, &[]).unwrap();

        assert!(!config.debug);
        assert_eq!(config.timeout, "1m0s");
    }

    #[test]
    fn test_an_invalid_passbolt_variable_is_an_error() {
        let environment = [layer(Origin::Environment, &[("timeout", "soon")])];

        let error = load(None, &environment, &[]).err().unwrap();

        assert!(
            format!("{error:#}").contains("PASSBOLT_TIMEOUT"),
            "{error:#}"
        );
    }

    #[test]
    fn test_a_false_flag_overrides_a_true_file_setting() {
        let (_directory, path) = file_with("config.toml", "tls_skip_verify = true\n");

        let config = load(Some(&path), &[], &[("tls_skip_verify", "false")]).unwrap();

        assert!(!config.tls_skip_verify);
    }

    #[test]
    fn test_the_deprecated_totp_token_is_used_when_the_current_one_is_empty() {
        let environment = [layer(Origin::GoEnvironment, &[("totp_token", "OLD")])];

        let config = load(None, &environment, &[]).unwrap();

        assert_eq!(config.mfa_totp_token, "OLD");
    }

    #[test]
    fn test_the_current_totp_token_wins_over_the_deprecated_one() {
        let (_directory, path) = file_with("c.toml", "totptoken = 'OLD'\nmfatotptoken = 'NEW'\n");

        let config = load(Some(&path), &[], &[("totp_token", "FLAG")]).unwrap();

        assert_eq!(config.mfa_totp_token, "NEW");
    }

    #[test]
    fn test_the_deprecated_offset_is_used_when_the_current_one_is_zero() {
        let config = load(None, &[], &[("totp_offset", "-1m")]).unwrap();

        assert_eq!(config.mfa_totp_offset_seconds().unwrap(), -60);
    }

    #[test]
    fn test_the_key_file_overrides_the_inline_key_of_the_same_source() {
        let (_directory, key) = file_with("key.asc", "from-file");

        let config = load(
            None,
            &[],
            &[
                ("user_private_key", "inline"),
                ("user_private_key_file", key.to_str().unwrap()),
            ],
        )
        .unwrap();

        assert_eq!(config.user_private_key, "from-file");
    }

    #[test]
    fn test_an_inline_key_flag_overrides_a_key_file_of_the_config_file() {
        let (_directory, key) = file_with("key.asc", "from-file");
        let (_config_directory, path) = file_with(
            "config.toml",
            &format!("user_private_key_file = '{}'\n", key.display()),
        );

        let config = load(Some(&path), &[], &[("user_private_key", "inline")]).unwrap();

        assert_eq!(config.user_private_key, "inline");
    }

    #[test]
    fn test_a_missing_key_file_is_reported_with_its_path() {
        let error = load(None, &[], &[("user_private_key_file", "/missing/key.asc")])
            .err()
            .unwrap();

        assert!(
            format!("{error:#}").contains("/missing/key.asc"),
            "{error:#}"
        );
    }

    #[test]
    fn test_private_key_text_missing() {
        let error = Config::default().private_key_text().err().unwrap();

        assert_eq!(error.to_string(), "userPrivateKey is not defined");
    }

    #[test]
    fn test_save_then_load_keeps_the_settings() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        let mut config = load(None, &[], &[("mfa_delay", "90")]).unwrap();
        config.server_address = "https://pass.example.com".into();
        config.mfa_retrys = 5;
        config.file = Some(path.clone());

        config.save().unwrap();
        let loaded = load(Some(&path), &[], &[]).unwrap();

        assert_eq!(loaded.server_address, "https://pass.example.com");
        assert_eq!(loaded.mfa_retrys, 5);
        assert_eq!(loaded.mfa_delay, "1m30s");
    }

    #[rstest]
    #[case::toml_of_go("go-passbolt-cli.toml", "serveraddress = 'https://go'\n")]
    #[case::json("config.json", "{}")]
    #[case::yaml("config.yaml", "")]
    fn test_save_writes_go_keys_in_go_files(#[case] name: &str, #[case] content: &str) {
        let (_directory, path) = file_with(name, content);
        let config = load(Some(&path), &[], &[("server_address", "https://saved")]).unwrap();

        config.save().unwrap();

        let saved = std::fs::read_to_string(&path).unwrap();
        assert!(saved.contains("serveraddress"), "{saved}");
        assert!(!saved.contains("server_address"), "{saved}");
        let loaded = load(Some(&path), &[], &[]).unwrap();
        assert_eq!(loaded.server_address, "https://saved");
    }

    #[test]
    fn test_save_keeps_the_environment_secrets_out_of_the_file() {
        let (_directory, path) = file_with("config.toml", "user_password = 'stored'\n");
        let environment = [
            layer(Origin::Environment, &[("user_password", "exported")]),
            layer(Origin::GoEnvironment, &[("mfa_totp_token", "EXPORTED")]),
        ];
        let config = load(Some(&path), &environment, &[]).unwrap();

        config.save().unwrap();

        let saved = std::fs::read_to_string(&path).unwrap();
        assert!(saved.contains("stored"), "{saved}");
        assert!(!saved.contains("exported"), "{saved}");
        assert!(!saved.contains("EXPORTED"), "{saved}");
    }

    #[test]
    fn test_masked_settings_hide_the_secrets() {
        let config = load(None, &[], &[("user_password", "hunter2")]).unwrap();

        let shown = config.masked_settings();

        assert!(!shown.contains("hunter2"), "{shown}");
        assert!(shown.contains("user_password:********"), "{shown}");
    }

    #[cfg(unix)]
    #[test]
    fn test_save_restricts_an_existing_file_to_its_owner() {
        use std::os::unix::fs::PermissionsExt;
        let (_directory, path) = file_with("config.toml", "");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let config = load(Some(&path), &[], &[]).unwrap();

        config.save().unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn test_reading_restricts_the_file_to_its_owner() {
        use std::os::unix::fs::PermissionsExt;
        let (_directory, path) = file_with("config.toml", "");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        load(Some(&path), &[], &[]).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn test_save_creates_a_directory_and_a_file_for_their_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("nested/config.toml");
        let mut config = load(None, &[], &[]).unwrap();
        config.file = Some(path.clone());

        config.save().unwrap();

        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
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
