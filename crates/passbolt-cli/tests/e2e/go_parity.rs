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

//! go-passbolt-cli command lines, variables and config files against the server. Only the
//! name pinning of the test setup (`PASSBOLT_RESOLVE`) is ours.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use predicates::str::contains;

use crate::common::{current_user_id, Account, UNKNOWN_ID};

fn setting(name: &str) -> String {
    std::env::var(format!("PASSBOLT_E2E_{name}"))
        .unwrap_or_else(|_| panic!("PASSBOLT_E2E_{name} is not set, see .env.e2e.example"))
}

fn tls_skip_verify() -> bool {
    std::env::var("PASSBOLT_E2E_TLS_SKIP_VERIFY").is_ok_and(|value| value == "true")
}

/// A home without any config file, and no variable but the name pinning of the test setup.
struct GoHome {
    directory: tempfile::TempDir,
}

impl GoHome {
    fn new() -> Self {
        Self {
            directory: tempfile::tempdir().unwrap(),
        }
    }

    fn config_dir(&self) -> PathBuf {
        self.directory.path().join(".config")
    }

    fn go_config(&self) -> PathBuf {
        self.config_dir()
            .join("go-passbolt-cli/go-passbolt-cli.toml")
    }

    fn passbolt(&self) -> Command {
        let mut command = assert_cmd::cargo::cargo_bin_cmd!("passbolt");
        command
            .env_clear()
            .env("HOME", self.directory.path())
            .env("XDG_CONFIG_HOME", self.config_dir())
            .current_dir(self.directory.path());
        if let Ok(resolve) = std::env::var("PASSBOLT_E2E_RESOLVE") {
            command.env("PASSBOLT_RESOLVE", resolve);
        }
        command
    }

    /// `passbolt --serverAddress … --userPrivateKeyFile … --mfaMode none [--tlsSkipVerify]`.
    fn with_go_flags(&self) -> Command {
        let mut command = self.passbolt();
        command
            .args(["--serverAddress", &setting("SERVER_ADDRESS")])
            .args(["--userPrivateKeyFile", &setting("USER_PRIVATE_KEY_FILE")])
            .args(["--mfaMode", "none"]);
        if tls_skip_verify() {
            command.arg("--tlsSkipVerify");
        }
        command
    }
}

fn me_id_of(output: &[u8]) -> String {
    let user: serde_json::Value = serde_json::from_slice(output).unwrap();
    user["id"].as_str().unwrap().to_string()
}

fn assert_is_me(output: &[u8]) {
    assert_eq!(me_id_of(output), current_user_id(Account::User));
}

#[test]
fn go_flags_log_in() {
    let output = GoHome::new()
        .with_go_flags()
        .args(["--userPassword", &setting("USER_PASSWORD")])
        .args(["get", "user", "--id", "me", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_is_me(&output);
}

#[test]
fn the_password_piped_on_stdin_logs_in() {
    let output = GoHome::new()
        .with_go_flags()
        .args(["get", "user", "--id", "me", "--json"])
        .write_stdin(format!("{}\n", setting("USER_PASSWORD")))
        .assert()
        .success()
        .stderr(contains("Enter Password:"))
        .get_output()
        .stdout
        .clone();

    assert_is_me(&output);
}

#[test]
fn go_variables_log_in() {
    let home = GoHome::new();
    let mut command = home.passbolt();
    command
        .env("SERVERADDRESS", setting("SERVER_ADDRESS"))
        .env(
            "USERPRIVATEKEY",
            std::fs::read_to_string(setting("USER_PRIVATE_KEY_FILE")).unwrap(),
        )
        .env("USERPASSWORD", setting("USER_PASSWORD"))
        .env("MFAMODE", "none")
        .env("TIMEOUT", "1m0s");
    if tls_skip_verify() {
        command.env("TLSSKIPVERIFY", "true");
    }

    let output = command
        .args(["get", "user", "--id", "me", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_is_me(&output);
}

fn write_go_config(path: &Path) {
    let key = std::fs::read_to_string(setting("USER_PRIVATE_KEY_FILE")).unwrap();
    let content = format!(
        "debug = false\nmfadelay = '1m0s'\nmfamode = 'none'\nmfaretrys = '3'\n\
         mfatotpoffset = '0s'\nmfatotptoken = ''\nserveraddress = '{}'\ntimeout = '1m0s'\n\
         tlsclientcert = ''\ntlsclientprivatekey = ''\ntlsskipverify = {}\ntotpoffset = '0s'\n\
         totptoken = ''\nuserpassword = '{}'\nuserprivatekey = '''\n{key}'''\nworkers = 2\n",
        setting("SERVER_ADDRESS"),
        tls_skip_verify(),
        setting("USER_PASSWORD"),
    );
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

#[test]
fn a_config_file_written_by_go_passbolt_cli_logs_in() {
    let home = GoHome::new();
    write_go_config(&home.go_config());

    let output = home
        .passbolt()
        .args(["--debug", "get", "user", "--id", "me", "--json"])
        .assert()
        .success()
        .stderr(contains(format!(
            "Using config file: {}",
            home.go_config().display()
        )))
        .get_output()
        .stdout
        .clone();

    assert_is_me(&output);
}

#[test]
fn verify_with_go_flags_then_logs_in_with_the_saved_verification() {
    let home = GoHome::new();
    let config = home.directory.path().join("verified.toml");

    home.with_go_flags()
        .args(["--config", config.to_str().unwrap()])
        .args(["--userPassword", &setting("USER_PASSWORD"), "verify"])
        .assert()
        .success()
        .stdout("Verification Enabled\n");

    let saved = std::fs::read_to_string(&config).unwrap();
    assert!(
        saved.contains("server_verify_token = \"gpgauthv1.3.0|"),
        "the go token"
    );
    assert!(
        saved.contains("BEGIN PGP PUBLIC KEY BLOCK"),
        "the pinned key"
    );
    assert!(!saved.contains("user_private_key_file"));
    let output = home
        .passbolt()
        .args(["--config", config.to_str().unwrap()])
        .args(["get", "user", "--id", "me", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_is_me(&output);
}

#[test]
fn an_error_prints_one_line_and_exits_with_code_1() {
    GoHome::new()
        .with_go_flags()
        .args(["--userPassword", &setting("USER_PASSWORD")])
        .args(["get", "resource", "--id", UNKNOWN_ID])
        .assert()
        .code(1)
        .stderr(predicates::str::starts_with("Error: "))
        .stderr(contains("\nCaused by").not());
}

#[test]
fn a_wrong_password_fails_with_code_1() {
    GoHome::new()
        .with_go_flags()
        .args(["--userPassword", "not the password"])
        .args(["get", "user", "--id", "me"])
        .assert()
        .code(1)
        .stderr(contains("Error: logging in"));
}

#[test]
fn the_version_flag_needs_no_server() {
    GoHome::new()
        .passbolt()
        .arg("-v")
        .assert()
        .success()
        .stdout(predicates::str::starts_with("passbolt version "));
}
