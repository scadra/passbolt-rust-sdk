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

//! go-passbolt-cli command lines, environment and config files, without a server: the CLI
//! must take them as go-passbolt-cli does.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use predicates::str::contains;

/// An address nothing listens on: the command fails once it tries to connect.
const NO_SERVER: &str = "http://127.0.0.1:1";

/// A home of its own, with no config file and no variable from the test environment.
struct Home {
    directory: tempfile::TempDir,
}

impl Home {
    fn new() -> Self {
        Self {
            directory: tempfile::tempdir().unwrap(),
        }
    }

    fn path(&self) -> &Path {
        self.directory.path()
    }

    fn config_dir(&self) -> PathBuf {
        self.path().join(".config")
    }

    fn our_config(&self) -> PathBuf {
        self.config_dir().join("passbolt/config.toml")
    }

    fn go_config(&self) -> PathBuf {
        self.config_dir()
            .join("go-passbolt-cli/go-passbolt-cli.toml")
    }

    fn passbolt(&self) -> Command {
        let mut command = assert_cmd::cargo::cargo_bin_cmd!("passbolt");
        command
            .env_clear()
            .env("HOME", self.path())
            .env("XDG_CONFIG_HOME", self.config_dir())
            .current_dir(self.path());
        command
    }
}

fn write_file(path: &Path, content: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

fn fixture_key(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../passbolt-sdk/tests/fixtures/keys")
        .join(name)
}

fn ada_key() -> String {
    fixture_key("ada_private.asc").to_str().unwrap().to_string()
}

fn ada_key_text() -> String {
    std::fs::read_to_string(fixture_key("ada_private.asc")).unwrap()
}

#[test]
fn no_arguments_prints_the_help_on_stdout() {
    Home::new()
        .passbolt()
        .assert()
        .code(0)
        .stdout(contains("Usage"))
        .stderr("");
}

#[test]
fn a_command_without_its_subcommand_prints_its_help() {
    Home::new()
        .passbolt()
        .arg("create")
        .assert()
        .code(0)
        .stdout(contains("resource"));
}

#[test]
fn a_usage_error_exits_with_code_1() {
    Home::new()
        .passbolt()
        .args(["--no-such-flag", "list", "resource"])
        .assert()
        .code(1);
}

#[rstest::rstest]
#[case("-v")]
#[case("--version")]
#[case("-V")]
fn the_version_follows_go_passbolt_cli_template(#[case] flag: &str) {
    let output = Home::new()
        .passbolt()
        .arg(flag)
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let version = String::from_utf8(output).unwrap();
    assert!(follows_version_template(&version), "{version}");
}

/// `passbolt version X (Built on DATE from Git SHA SHA)`, optionally followed by ` dirty`.
fn follows_version_template(version: &str) -> bool {
    let Some(rest) = version.strip_prefix("passbolt version ") else {
        return false;
    };
    let rest = rest.trim_end().trim_end_matches(" dirty");
    rest.contains(" (Built on ") && rest.contains(" from Git SHA ") && rest.ends_with(')')
}

#[test]
fn a_missing_server_address_is_reported_first() {
    Home::new()
        .passbolt()
        .args(["list", "resource"])
        .assert()
        .code(1)
        .stderr("Error: serverAddress is not defined\n");
}

#[test]
fn a_missing_private_key_is_reported() {
    Home::new()
        .passbolt()
        .args(["--serverAddress", NO_SERVER, "list", "resource"])
        .assert()
        .code(1)
        .stderr("Error: userPrivateKey is not defined\n");
}

#[test]
fn a_missing_password_is_read_from_stdin() {
    Home::new()
        .passbolt()
        .args([
            "--serverAddress",
            NO_SERVER,
            "--userPrivateKeyFile",
            &ada_key(),
        ])
        .args(["list", "resource"])
        .write_stdin("secret\n")
        .assert()
        .code(1)
        .stderr(contains("Enter Password:"))
        .stderr(contains("reading Password").not())
        .stderr(contains("127.0.0.1:1"));
}

#[test]
fn verify_reads_a_missing_password_from_stdin() {
    Home::new()
        .passbolt()
        .args([
            "--serverAddress",
            NO_SERVER,
            "--userPrivateKeyFile",
            &ada_key(),
        ])
        .arg("verify")
        .write_stdin("secret\n")
        .assert()
        .code(1)
        .stderr(contains("Enter Password:"))
        .stderr(contains("127.0.0.1:1"));
}

#[test]
fn an_empty_stdin_fails_reading_the_password() {
    Home::new()
        .passbolt()
        .args([
            "--serverAddress",
            NO_SERVER,
            "--userPrivateKeyFile",
            &ada_key(),
        ])
        .args(["list", "resource"])
        .write_stdin("")
        .assert()
        .code(1)
        .stderr(contains("Error: reading Password: EOF"));
}

#[test]
fn go_environment_variables_are_read() {
    Home::new()
        .passbolt()
        .env("SERVERADDRESS", NO_SERVER)
        .env("USERPRIVATEKEY", ada_key_text())
        .env("USERPASSWORD", "p")
        .args(["list", "resource"])
        .assert()
        .code(1)
        .stderr(contains("127.0.0.1:1"))
        .stderr(contains("Enter Password:").not());
}

#[test]
fn our_variables_win_over_go_variables_and_flags_over_both() {
    let home = Home::new();

    home.passbolt()
        .env("SERVERADDRESS", "https://go.test")
        .env("PASSBOLT_SERVER_ADDRESS", "https://ours.test")
        .env("MFAMODE", "none")
        .env("PASSBOLT_PROXY", "http://proxy.test")
        .args(["--proxy", "http://flag.test", "configure"])
        .assert()
        .success();

    let saved = std::fs::read_to_string(home.our_config()).unwrap();
    assert!(saved.contains("https://ours.test"), "{saved}");
    assert!(saved.contains("mfa_mode = \"none\""), "{saved}");
    assert!(saved.contains("http://flag.test"), "{saved}");
}

#[test]
fn configure_keeps_the_secrets_of_go_variables_out_of_the_file() {
    let home = Home::new();

    home.passbolt()
        .env("USERPASSWORD", "exported")
        .env("MFATOTPTOKEN", "JBSWY3DPEHPK3PXP")
        .args(["configure", "--serverAddress", "https://x.test"])
        .assert()
        .success();

    let saved = std::fs::read_to_string(home.our_config()).unwrap();
    assert!(!saved.contains("exported"), "{saved}");
    assert!(!saved.contains("JBSWY3DPEHPK3PXP"), "{saved}");
}

const GO_CONFIG: &str = "serveraddress = 'http://127.0.0.1:1'\nmfamode = 'none'\n\
                         mfadelay = '1m0s'\nmfaretrys = '3'\nmfatotpoffset = '0s'\n\
                         timeout = '1m0s'\ntlsskipverify = false\nworkers = 2\n\
                         userpassword = 'p'\n";

#[test]
fn go_passbolt_cli_config_file_is_read_when_ours_does_not_exist() {
    let home = Home::new();
    write_file(&home.go_config(), GO_CONFIG);

    home.passbolt()
        .args([
            "--debug",
            "--userPrivateKeyFile",
            &ada_key(),
            "list",
            "resource",
        ])
        .assert()
        .code(1)
        .stderr(contains(format!(
            "Using config file: {}",
            home.go_config().display()
        )))
        .stderr(contains(format!("Loading file: {}", ada_key())))
        .stderr(contains("127.0.0.1:1"));
}

#[test]
fn our_config_file_wins_over_go_passbolt_cli_one() {
    let home = Home::new();
    write_file(&home.go_config(), GO_CONFIG);
    write_file(
        &home.our_config(),
        "server_address = 'http://127.0.0.2:1'\n",
    );

    home.passbolt()
        .args([
            "--debug",
            "--userPrivateKeyFile",
            &ada_key(),
            "--userPassword",
            "p",
        ])
        .args(["list", "resource"])
        .assert()
        .code(1)
        .stderr(contains(format!(
            "Using config file: {}",
            home.our_config().display()
        )))
        .stderr(contains("127.0.0.2:1"));
}

#[test]
fn configure_updates_go_passbolt_cli_config_file_with_its_keys() {
    let home = Home::new();
    write_file(&home.go_config(), GO_CONFIG);

    home.passbolt()
        .args(["configure", "--mfaMode", "noninteractive-totp"])
        .assert()
        .success()
        .stdout("");

    let saved = std::fs::read_to_string(home.go_config()).unwrap();
    assert!(
        saved.contains("mfamode = \"noninteractive-totp\""),
        "{saved}"
    );
    assert!(
        saved.contains("serveraddress = \"http://127.0.0.1:1\""),
        "{saved}"
    );
    assert!(saved.contains("mfadelay = \"1m0s\""), "{saved}");
    assert!(!home.our_config().exists());
}

#[cfg(unix)]
#[test]
fn reading_a_config_file_restricts_it_to_its_owner() {
    use std::os::unix::fs::PermissionsExt;
    let home = Home::new();
    write_file(&home.go_config(), GO_CONFIG);
    std::fs::set_permissions(home.go_config(), std::fs::Permissions::from_mode(0o644)).unwrap();

    home.passbolt()
        .args(["--userPrivateKeyFile", &ada_key(), "list", "resource"])
        .assert()
        .code(1);

    let mode = std::fs::metadata(home.go_config())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
}

#[rstest::rstest]
#[case::yaml("custom.yaml", "serveraddress: http://127.0.0.1:1\nuserpassword: p\n")]
#[case::json(
    "custom.json",
    "{\"serverAddress\": \"http://127.0.0.1:1\", \"userPassword\": \"p\"}"
)]
fn a_config_file_is_read_in_the_format_of_its_extension(#[case] name: &str, #[case] content: &str) {
    let home = Home::new();
    let config = home.path().join(name);
    write_file(&config, content);

    home.passbolt()
        .args(["--config", config.to_str().unwrap()])
        .args(["--userPrivateKeyFile", &ada_key(), "list", "resource"])
        .assert()
        .code(1)
        .stderr(contains("127.0.0.1:1"));
}

#[test]
fn configure_saves_the_key_content_not_its_path() {
    let home = Home::new();

    home.passbolt()
        .args(["configure", "--userPrivateKeyFile", &ada_key()])
        .assert()
        .success();

    let saved = std::fs::read_to_string(home.our_config()).unwrap();
    assert!(saved.contains("BEGIN PGP PRIVATE KEY BLOCK"), "{saved}");
    assert!(!saved.contains("ada_private.asc"), "{saved}");
}

#[test]
fn configure_with_debug_prints_the_settings_without_the_secrets() {
    let home = Home::new();

    home.passbolt()
        .args(["configure", "--debug", "--userPassword", "hunter2"])
        .assert()
        .success()
        .stdout(contains("Saved: map["))
        .stdout(contains("debug:true"))
        .stdout(contains("hunter2").not());

    let saved = std::fs::read_to_string(home.our_config()).unwrap();
    assert!(saved.contains("debug = true"), "{saved}");
}

#[rstest::rstest]
#[case(&["--mfaTotpOffset", "-1m"], "mfa_totp_offset = \"-1m0s\"")]
#[case(&["--mfaTotpOffset=-30s"], "mfa_totp_offset = \"-30s\"")]
#[case(&["--timeout", "1m30s"], "timeout = \"1m30s\"")]
#[case(&["--timeout", "90"], "timeout = \"1m30s\"")]
#[case(&["--mfaDelay", "500ms"], "mfa_delay = \"500ms\"")]
#[case(&["--tlsSkipVerify"], "tls_skip_verify = true")]
#[case(&["--tlsSkipVerify=false"], "tls_skip_verify = false")]
fn configure_saves_go_values(#[case] flags: &[&str], #[case] expected: &str) {
    let home = Home::new();
    write_file(&home.our_config(), "tls_skip_verify = true\n");

    home.passbolt()
        .arg("configure")
        .args(flags)
        .assert()
        .success();

    let saved = std::fs::read_to_string(home.our_config()).unwrap();
    assert!(saved.contains(expected), "{saved}");
}

#[test]
fn an_invalid_duration_is_reported_with_go_message() {
    Home::new()
        .passbolt()
        .args(["--timeout", "1d", "configure"])
        .assert()
        .code(1)
        .stderr(contains("unknown unit \"d\" in duration \"1d\""));
}

#[rstest::rstest]
#[case("--totpToken", "JBSWY3DPEHPK3PXP", "totpToken", "mfaTotpToken")]
#[case("--totpOffset", "30s", "totpOffset", "mfaTotpOffset")]
fn a_deprecated_flag_is_taken_with_a_warning(
    #[case] flag: &str,
    #[case] value: &str,
    #[case] deprecated: &str,
    #[case] replacement: &str,
) {
    let home = Home::new();

    home.passbolt()
        .args([flag, value, "configure"])
        .assert()
        .success()
        .stderr(contains(format!(
            "Flag --{deprecated} has been deprecated, use --{replacement} instead"
        )));
}

#[rstest::rstest]
#[case(
    "--tlsClientCert",
    "client TLS private key is empty, but client TLS cert was set"
)]
#[case(
    "--tlsClientPrivateKey",
    "client TLS cert is empty, but client TLS private key was set"
)]
fn an_incomplete_client_certificate_is_refused(#[case] flag: &str, #[case] message: &str) {
    Home::new()
        .passbolt()
        .args([
            "--serverAddress",
            NO_SERVER,
            "--userPrivateKeyFile",
            &ada_key(),
        ])
        .args(["--userPassword", "p", flag, "pem", "list", "resource"])
        .assert()
        .code(1)
        .stderr(contains(message));
}

#[test]
fn debug_prints_the_worker_count_and_the_requests() {
    Home::new()
        .passbolt()
        .env("DEBUG", "true")
        .args([
            "--serverAddress",
            NO_SERVER,
            "--userPrivateKeyFile",
            &ada_key(),
        ])
        .args(["--userPassword", "p", "list", "resource"])
        .assert()
        .code(1)
        .stderr(contains("Autodetected Worker Count: "))
        .stderr(contains("[debug] POST http://127.0.0.1:1/auth/login.json"));
}

#[test]
fn completion_survives_a_reader_that_stops_early() {
    use std::io::BufRead;
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_passbolt"))
        .args(["completion", "bash"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut first_line = String::new();
    std::io::BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut first_line)
        .unwrap();

    let output = child.wait_with_output().unwrap();

    assert_ne!(first_line, "");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("panicked"), "{stderr}");
    assert!(output.status.success(), "{stderr}");
}

#[rstest::rstest]
#[case::markdown(&[], "doc", &["passbolt.md", "passbolt_create_resource.md"])]
#[case::markdown_short_flag(&["-t", "markdown"], "doc", &["passbolt_list_user.md"])]
#[case::man(&["--type", "man"], "man", &["passbolt.1", "passbolt-create-resource.1"])]
fn gendoc_writes_one_page_per_command_like_cobra(
    #[case] flags: &[&str],
    #[case] directory: &str,
    #[case] expected: &[&str],
) {
    let home = Home::new();

    home.passbolt()
        .arg("gendoc")
        .args(flags)
        .assert()
        .success()
        .stdout("");

    for name in expected {
        assert!(
            home.path().join(directory).join(name).exists(),
            "{name} missing"
        );
    }
}

#[test]
fn a_timeout_bounds_the_whole_command() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let connections: Vec<_> = listener.incoming().collect();
        drop(connections);
    });
    let started = std::time::Instant::now();

    Home::new()
        .passbolt()
        .args(["--serverAddress", &format!("http://{address}")])
        .args(["--userPrivateKeyFile", &ada_key(), "--userPassword", "p"])
        .args(["--timeout", "1s", "list", "resource"])
        .timeout(std::time::Duration::from_secs(15))
        .assert()
        .code(1);

    assert!(started.elapsed() < std::time::Duration::from_secs(10));
}
