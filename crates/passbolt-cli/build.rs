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

//! The version text of `passbolt --version`, as go-passbolt-cli writes it:
//! `version X (Built on DATE from Git SHA SHA[ dirty])`.
//!
//! `PASSBOLT_BUILD_DATE`, `PASSBOLT_BUILD_COMMIT` and `PASSBOLT_BUILD_DIRTY` (true/false) set
//! them for a release build; otherwise they come from git and the clock.

use std::process::Command;

fn git(arguments: &[&str]) -> Option<String> {
    let output = Command::new("git").args(arguments).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn main() {
    for name in [
        "PASSBOLT_BUILD_DATE",
        "PASSBOLT_BUILD_COMMIT",
        "PASSBOLT_BUILD_DIRTY",
        "SOURCE_DATE_EPOCH",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    if let Some(git_directory) = git(&["rev-parse", "--absolute-git-dir"]) {
        println!("cargo:rerun-if-changed={git_directory}/HEAD");
        println!("cargo:rerun-if-changed={git_directory}/index");
    }
    println!("cargo:rerun-if-changed=src");

    let commit = std::env::var("PASSBOLT_BUILD_COMMIT")
        .ok()
        .or_else(|| git(&["rev-parse", "HEAD"]))
        .unwrap_or_else(|| "unknown".into());
    let dirty = std::env::var("PASSBOLT_BUILD_DIRTY").map_or_else(
        |_| {
            git(&["status", "--porcelain", "--untracked-files=no"])
                .is_some_and(|status| !status.is_empty())
        },
        |value| value == "true",
    );
    let date = std::env::var("PASSBOLT_BUILD_DATE").unwrap_or_else(|_| {
        let seconds = std::env::var("SOURCE_DATE_EPOCH")
            .ok()
            .and_then(|epoch| epoch.parse::<i64>().ok())
            .unwrap_or_else(|| chrono::Utc::now().timestamp());
        chrono::DateTime::from_timestamp(seconds, 0)
            .unwrap_or_default()
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string()
    });

    let version = env!("CARGO_PKG_VERSION");
    let dirty = if dirty { " dirty" } else { "" };
    println!(
        "cargo:rustc-env=PASSBOLT_VERSION_TEXT=version {version} (Built on {date} from Git SHA \
         {commit}){dirty}"
    );
}
