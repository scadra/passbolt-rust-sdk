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

use assert_cmd::Command;
use predicates::prelude::*;
use predicates::str::contains;

fn passbolt() -> Command {
    assert_cmd::cargo::cargo_bin_cmd!("passbolt")
}

#[test]
fn test_help_flag() {
    passbolt()
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("Usage"));
}

#[test]
fn test_version_flag() {
    passbolt()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicates::str::starts_with(
            "passbolt version 0.1.0 (Built on ",
        ))
        .stdout(contains(" from Git SHA "));
}

#[test]
fn test_subcommand_help() {
    passbolt()
        .args(["create", "resource", "--help"])
        .assert()
        .success()
        .stdout(contains("Usage"));
}

#[test]
fn test_list_resource_fails_without_server() {
    // Point to an unreachable address so no real server is contacted.
    passbolt()
        .env("PASSBOLT_SERVER_ADDRESS", "http://127.0.0.1:1")
        .env("PASSBOLT_USER_PASSWORD", "dummy")
        .env("PASSBOLT_USER_PRIVATE_KEY", "not-a-key")
        .args(["list", "resource"])
        .assert()
        .failure();
}

#[test]
fn test_unknown_subcommand_fails() {
    passbolt().arg("nonexistent-command").assert().code(1);
}

#[test]
fn test_configure_writes_to_the_config_override_only() {
    let home = tempfile::tempdir().unwrap();
    let config = home.path().join("custom.toml");

    passbolt()
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .env("PASSBOLT_CONFIG", &config)
        .args(["configure", "--server-address", "https://example.test"])
        .assert()
        .success();

    assert!(std::fs::read_to_string(&config)
        .unwrap()
        .contains("https://example.test"));
    assert!(
        !home.path().join(".config").exists(),
        "default config location was written"
    );
}

#[test]
fn test_share_accepts_a_negative_type_to_revoke() {
    let output = passbolt()
        .env(
            "PASSBOLT_CONFIG",
            std::env::temp_dir().join("passbolt-cli-test-none.toml"),
        )
        .args([
            "share", "resource", "--id", "x", "--type", "-1", "--user", "y",
        ])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("unexpected argument"), "{stderr}");
}

#[test]
fn test_completion_generates_a_script() {
    passbolt()
        .args(["completion", "bash"])
        .assert()
        .success()
        .stdout(contains("passbolt"));
}

#[test]
fn test_gendoc_writes_markdown() {
    let directory = tempfile::tempdir().unwrap();

    passbolt()
        .args(["gendoc", "--output-dir", directory.path().to_str().unwrap()])
        .assert()
        .success();

    let written = std::fs::read_dir(directory.path()).unwrap().count();
    assert_ne!(written, 0, "no documentation written");
}

#[test]
fn test_configure_persists_every_given_setting() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.toml");

    passbolt()
        .env("PASSBOLT_CONFIG", &config)
        .args([
            "configure",
            "--server-address",
            "https://example.test",
            "--proxy",
            "http://proxy.test:8080",
            "--mfa-mode",
            "none",
        ])
        .assert()
        .success();

    let saved = std::fs::read_to_string(&config).unwrap();
    for expected in [
        "https://example.test",
        "http://proxy.test:8080",
        "mfa_mode = \"none\"",
    ] {
        assert!(saved.contains(expected), "{expected} missing: {saved}");
    }
}

fn configure_in(config: &std::path::Path) -> Command {
    let mut command = passbolt();
    command
        .env_remove("PASSBOLT_SERVER_ADDRESS")
        .env("PASSBOLT_CONFIG", config)
        .arg("configure");
    command
}

fn fixture_key(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../passbolt-sdk/tests/fixtures/keys")
        .join(name)
}

#[test]
fn configure_refuses_to_overwrite_an_invalid_config_file() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.toml");
    std::fs::write(&config, "server_address = [not toml").unwrap();

    configure_in(&config)
        .args(["--proxy", "http://proxy.test:8080"])
        .assert()
        .failure()
        .stderr(contains(config.to_str().unwrap()));

    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        "server_address = [not toml"
    );
}

#[test]
fn a_command_fails_on_an_invalid_config_file() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.toml");
    std::fs::write(&config, "server_address = [not toml").unwrap();

    passbolt()
        .args(["--config", config.to_str().unwrap(), "list", "resource"])
        .assert()
        .failure()
        .stderr(contains(config.to_str().unwrap()));
}

#[cfg(unix)]
#[test]
fn configure_restricts_an_existing_config_file_to_its_owner() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.toml");
    std::fs::write(&config, "server_address = \"https://example.test\"\n").unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o644)).unwrap();

    configure_in(&config)
        .args(["--mfa-mode", "none"])
        .assert()
        .success();

    let mode = std::fs::metadata(&config).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn configure_saves_the_server_address_from_the_environment() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.toml");

    configure_in(&config)
        .env("PASSBOLT_SERVER_ADDRESS", "https://from-env.test")
        .assert()
        .success();

    let saved = std::fs::read_to_string(&config).unwrap();
    assert!(
        saved.contains("server_address = \"https://from-env.test\""),
        "{saved}"
    );
}

#[test]
fn configure_saves_the_server_verify_token_from_the_environment() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.toml");

    configure_in(&config)
        .env("PASSBOLT_SERVER_VERIFY_TOKEN", "token-from-env")
        .assert()
        .success();

    let saved = std::fs::read_to_string(&config).unwrap();
    assert!(
        saved.contains("server_verify_token = \"token-from-env\""),
        "{saved}"
    );
}

#[test]
fn successive_configure_runs_accumulate_settings() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.toml");

    configure_in(&config)
        .args(["--server-address", "https://example.test"])
        .assert()
        .success();
    configure_in(&config)
        .args(["--proxy", "http://proxy.test:8080"])
        .assert()
        .success();

    let saved = std::fs::read_to_string(&config).unwrap();
    assert!(saved.contains("https://example.test"), "{saved}");
    assert!(saved.contains("http://proxy.test:8080"), "{saved}");
}

#[test]
fn configure_fails_on_a_missing_tls_client_certificate_file() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.toml");
    let missing = directory.path().join("missing.pem");

    configure_in(&config)
        .args(["--tls-client-cert-file", missing.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(contains("Cannot read TLS client cert file"))
        .stderr(contains(missing.to_str().unwrap()));

    assert!(!config.exists());
}

#[test]
fn a_command_fails_on_a_missing_tls_client_certificate_file() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing.pem");

    passbolt()
        .env("PASSBOLT_CONFIG", directory.path().join("config.toml"))
        .args([
            "--server-address",
            "http://127.0.0.1:1",
            "--tls-client-cert-file",
            missing.to_str().unwrap(),
            "list",
            "resource",
        ])
        .assert()
        .failure()
        .stderr(contains("Cannot read TLS client cert file"))
        .stderr(contains(missing.to_str().unwrap()));
}

#[test]
fn an_invalid_resolve_fails_before_any_network_access() {
    let directory = tempfile::tempdir().unwrap();

    passbolt()
        .env("PASSBOLT_CONFIG", directory.path().join("config.toml"))
        .args([
            "--server-address",
            "http://127.0.0.1:1",
            "--user-private-key-file",
            fixture_key("ada_private.asc").to_str().unwrap(),
            "--user-password",
            "p",
            "--resolve",
            "bad",
            "verify",
        ])
        .assert()
        .failure()
        .stderr(contains("Invalid --resolve"));
}

#[test]
fn the_config_flag_selects_the_file_a_command_reads() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("f.toml");
    std::fs::write(&config, "server_address = \"http://127.0.0.1:1\"\n").unwrap();

    passbolt()
        .env_remove("PASSBOLT_SERVER_ADDRESS")
        .env_remove("PASSBOLT_CONFIG")
        .args([
            "--config",
            config.to_str().unwrap(),
            "--user-private-key-file",
            fixture_key("ada_private.asc").to_str().unwrap(),
            "--user-password",
            "p",
            "verify",
        ])
        .assert()
        .failure()
        .stderr(contains("127.0.0.1:1"));
}

#[test]
fn gendoc_writes_man_pages() {
    let directory = tempfile::tempdir().unwrap();

    passbolt()
        .args([
            "gendoc",
            "--doc-type",
            "man",
            "--output-dir",
            directory.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    let names: Vec<String> = std::fs::read_dir(directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(names.contains(&"passbolt.1".to_string()), "{names:?}");
    assert!(names.iter().all(|name| name.ends_with(".1")), "{names:?}");
}

#[test]
fn timeout_aborts_a_request_to_a_silent_server() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let connections: Vec<_> = listener.incoming().collect();
        drop(connections);
    });
    let directory = tempfile::tempdir().unwrap();
    let started = std::time::Instant::now();

    passbolt()
        .env("PASSBOLT_CONFIG", directory.path().join("config.toml"))
        .args([
            "--server-address",
            &format!("http://{address}"),
            "--user-private-key-file",
            fixture_key("ada_private.asc").to_str().unwrap(),
            "--user-password",
            "p",
            "--timeout",
            "1s",
            "verify",
        ])
        .timeout(std::time::Duration::from_secs(15))
        .output()
        .unwrap();

    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "still waiting after {elapsed:?}"
    );
}

#[test]
fn an_environment_variable_takes_precedence_over_the_config_file() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.toml");
    std::fs::write(&config, "server_verify_token = \"token-from-file\"\n").unwrap();

    configure_in(&config)
        .env("PASSBOLT_SERVER_VERIFY_TOKEN", "token-from-env")
        .assert()
        .success();

    let saved = std::fs::read_to_string(&config).unwrap();
    assert!(
        saved.contains("server_verify_token = \"token-from-env\""),
        "{saved}"
    );
}

#[test]
fn gendoc_refuses_an_unknown_format() {
    let directory = tempfile::tempdir().unwrap();

    passbolt()
        .args([
            "gendoc",
            "-t",
            "pdf",
            "--output-dir",
            directory.path().to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(contains("pdf"));
}

#[test]
fn an_unknown_mfa_mode_is_none_as_for_go_passbolt_cli() {
    let directory = tempfile::tempdir().unwrap();

    passbolt()
        .env("PASSBOLT_CONFIG", directory.path().join("config.toml"))
        .args([
            "--serverAddress",
            "http://127.0.0.1:1",
            "--userPassword",
            "p",
        ])
        .args([
            "--userPrivateKeyFile",
            fixture_key("ada_private.asc").to_str().unwrap(),
        ])
        .args(["--mfaMode", "interactive", "list", "resource"])
        .assert()
        .code(1)
        .stderr(contains("127.0.0.1:1"))
        .stderr(contains("MFA").not());
}

#[test]
fn test_configure_keeps_the_environment_out_of_the_file() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.toml");

    passbolt()
        .env("PASSBOLT_CONFIG", &config)
        .env("PASSBOLT_USER_PASSWORD", "exported-for-one-run")
        .env("PASSBOLT_MFA_TOTP_TOKEN", "JBSWY3DPEHPK3PXP")
        .args(["configure", "--server-address", "https://passbolt.test"])
        .assert()
        .success();

    let saved = std::fs::read_to_string(&config).unwrap();
    assert!(saved.contains("https://passbolt.test"), "{saved}");
    assert!(!saved.contains("exported-for-one-run"), "{saved}");
    assert!(!saved.contains("JBSWY3DPEHPK3PXP"), "{saved}");
}

#[test]
fn test_configure_saves_what_is_given_on_the_command_line() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.toml");

    passbolt()
        .env("PASSBOLT_CONFIG", &config)
        .args(["configure", "--server-address", "https://passbolt.test"])
        .args(["--user-password", "typed-on-purpose"])
        .assert()
        .success();

    let saved = std::fs::read_to_string(&config).unwrap();
    assert!(saved.contains("typed-on-purpose"), "{saved}");
}
