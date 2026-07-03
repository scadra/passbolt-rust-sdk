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

//! With the `gopenpgp` feature, builds `gopenpgp/` as a C archive with Go (`GO`, else `go`)
//! and links it.

use std::env;
use std::path::PathBuf;
use std::process::Command;

/// The archive, `lib<ARCHIVE>.a`.
const ARCHIVE: &str = "passbolt_gopenpgp";

fn main() {
    println!("cargo:rerun-if-env-changed=GO");
    if env::var_os("CARGO_FEATURE_GOPENPGP").is_none() {
        return;
    }
    let target = |name: &str| env::var(format!("CARGO_CFG_TARGET_{name}")).unwrap_or_default();
    let (os, arch) = (target("OS"), target("ARCH"));
    if arch == "wasm32" {
        return;
    }
    println!("cargo:rerun-if-changed=gopenpgp");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let go = env::var("GO").unwrap_or_else(|_| "go".into());
    let status = Command::new(&go)
        .args(["build", "-buildmode=c-archive", "-trimpath", "-o"])
        .arg(out_dir.join(format!("lib{ARCHIVE}.a")))
        .arg(".")
        .current_dir("gopenpgp")
        .env("CGO_ENABLED", "1")
        .env("GOOS", go_os(&os))
        .env("GOARCH", go_arch(&arch))
        .status()
        .unwrap_or_else(|error| panic!("the gopenpgp feature needs Go ({go}): {error}"));
    assert!(status.success(), "go build of gopenpgp/ failed");

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static={ARCHIVE}");
    // What the Go runtime needs from the system.
    match os.as_str() {
        "macos" | "ios" => {
            println!("cargo:rustc-link-lib=framework=CoreFoundation");
            println!("cargo:rustc-link-lib=framework=Security");
        }
        "windows" => println!("cargo:rustc-link-lib=dylib=ws2_32"),
        "linux" => println!("cargo:rustc-link-lib=dylib=pthread"),
        _ => {}
    }
}

fn go_os(os: &str) -> &str {
    match os {
        "macos" => "darwin",
        os => os,
    }
}

fn go_arch(arch: &str) -> &str {
    match arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "386",
        arch => arch,
    }
}
