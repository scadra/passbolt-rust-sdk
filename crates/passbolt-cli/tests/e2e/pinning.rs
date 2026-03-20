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

//! `verify` pins the server key and the shared metadata key; a key that changed afterwards is
//! refused until it is trusted again with `verify --force`.

use std::path::{Path, PathBuf};

use predicates::str::contains;

use crate::common::{passbolt, share_with_user_id, unique_name, Cleanup};

/// A public key that is not the server's.
const OTHER_KEY: &str = include_str!("../../../passbolt-sdk/tests/fixtures/keys/server_public.asc");

/// A config file in its own directory, holding `content`.
fn config_with(content: &str) -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.toml");
    std::fs::write(&config, content).unwrap();
    (directory, config)
}

fn passbolt_with(config: &Path) -> assert_cmd::Command {
    let mut command = passbolt();
    command.env("PASSBOLT_CONFIG", config);
    command
}

fn verify(config: &Path, args: &[&str]) -> assert_cmd::assert::Assert {
    passbolt_with(config).arg("verify").args(args).assert()
}

/// A personal v5 resource made with `config`, shared with the recipient user.
fn share_new_resource(config: &Path) -> assert_cmd::assert::Assert {
    let output = passbolt_with(config)
        .args(["create", "resource", "--type", "v5-default", "--json"])
        .args(["--name", &unique_name("pinned"), "--password", "p"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let resource = Cleanup::new("resource", &serde_json::from_slice(&output).unwrap());
    passbolt_with(config)
        .args(["share", "resource", "--id", &resource.id])
        .args(["-u", &share_with_user_id(), "-t", "1"])
        .assert()
}

/// The pinned keys: the go-passbolt-cli token is new at each `verify`.
fn pins(config: &Path) -> String {
    let saved: toml::Table = toml::from_str(&std::fs::read_to_string(config).unwrap()).unwrap();
    format!(
        "metadata_key_fingerprint = {}\nserver_public_key = {}",
        saved["metadata_key_fingerprint"], saved["server_public_key"]
    )
}

#[test]
fn verify_again_keeps_the_same_pins() {
    let (_directory, config) = config_with("");
    verify(&config, &[]).success();
    let pinned = pins(&config);

    verify(&config, &[]).success();

    assert_eq!(pins(&config), pinned);
    assert!(pinned.contains("metadata_key_fingerprint"), "{pinned}");
}

#[test]
fn a_changed_server_key_is_refused_until_trusted_again() {
    let (_directory, config) = config_with(&format!("server_public_key = '''\n{OTHER_KEY}'''\n"));

    verify(&config, &[])
        .failure()
        .stderr(contains("server key changed"));
    passbolt_with(&config)
        .args(["get", "user", "--id", "me"])
        .assert()
        .failure();

    verify(&config, &["--force"]).success();
    passbolt_with(&config)
        .args(["get", "user", "--id", "me"])
        .assert()
        .success();
}

#[test]
fn a_changed_metadata_key_is_refused_until_trusted_again() {
    let (_directory, config) = config_with(&format!(
        "metadata_key_fingerprint = \"{}\"\n",
        "0".repeat(40)
    ));

    verify(&config, &[])
        .failure()
        .stderr(contains("metadata key changed"));
    share_new_resource(&config)
        .failure()
        .stderr(contains("passbolt verify"));

    verify(&config, &["--force"]).success();
    share_new_resource(&config).success();
}
