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
//! and links it. cgo compiles with the C compiler of the target: `CC_<target>` or `TARGET_CC`
//! as cc-rs reads them (cargo-ndk sets them), else `musl-gcc` for musl and the MinGW gcc for
//! Windows (MSVC does not link a Go archive); Apple targets get the clang target of their
//! minimum version, and iOS its SDK.

use std::env;
use std::path::PathBuf;
use std::process::Command;

/// The archive, `lib<ARCHIVE>.a`.
const ARCHIVE: &str = "passbolt_gopenpgp";

fn main() {
    println!("cargo:rerun-if-env-changed=GO");
    for name in [
        "TARGET_CC",
        "MACOSX_DEPLOYMENT_TARGET",
        "IPHONEOS_DEPLOYMENT_TARGET",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    if env::var_os("CARGO_FEATURE_GOPENPGP").is_none() {
        return;
    }
    let target = |name: &str| env::var(format!("CARGO_CFG_TARGET_{name}")).unwrap_or_default();
    let (os, arch, target_env) = (target("OS"), target("ARCH"), target("ENV"));
    let triple = env::var("TARGET").expect("TARGET");
    if arch == "wasm32" {
        return;
    }
    println!("cargo:rerun-if-changed=gopenpgp");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let go = env::var("GO").unwrap_or_else(|_| "go".into());
    let mut command = Command::new(&go);
    command
        .args(["build", "-buildmode=c-archive", "-trimpath", "-o"])
        .arg(out_dir.join(format!("lib{ARCHIVE}.a")))
        .arg(".")
        .current_dir("gopenpgp")
        .env("CGO_ENABLED", "1")
        .env("GOOS", go_os(&os))
        .env("GOARCH", go_arch(&arch));
    if arch == "arm" {
        command.env("GOARM", "7");
    }
    if let Some(cc) = c_compiler(&triple, &arch, &target_env) {
        command.env("CC", cc);
    }
    if let Some(flags) = apple_flags(&os, &arch, &triple) {
        command.env("CGO_CFLAGS", &flags).env("CGO_LDFLAGS", &flags);
    }
    let status = command
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
        // The Go runtime writes its crashes to the Android log.
        "android" => println!("cargo:rustc-link-lib=dylib=log"),
        _ => {}
    }
}

fn go_os(os: &str) -> &str {
    match os {
        "macos" => "darwin",
        os => os,
    }
}

/// The C compiler of `triple` as cc-rs finds it in the environment, else the one cgo needs.
fn c_compiler(triple: &str, arch: &str, target_env: &str) -> Option<String> {
    let names = [
        format!("CC_{triple}"),
        format!("CC_{}", triple.replace('-', "_")),
        "TARGET_CC".to_owned(),
    ];
    for name in &names {
        println!("cargo:rerun-if-env-changed={name}");
    }
    names
        .iter()
        .find_map(|name| env::var(name).ok())
        .or_else(|| match target_env {
            "musl" => Some("musl-gcc".to_owned()),
            "gnu" if triple.contains("-windows-") => Some(format!("{arch}-w64-mingw32-gcc")),
            _ => None,
        })
}

/// The flags clang compiles for an Apple `triple` with: its target and minimum version, and the
/// SDK of iOS.
fn apple_flags(os: &str, arch: &str, triple: &str) -> Option<String> {
    let clang_arch = if arch == "aarch64" { "arm64" } else { arch };
    let version = |name: &str, default: &str| env::var(name).unwrap_or_else(|_| default.into());
    match os {
        "macos" => Some(format!(
            "-target {clang_arch}-apple-macos{}",
            version("MACOSX_DEPLOYMENT_TARGET", "11.0")
        )),
        "ios" => {
            let simulator = triple.ends_with("-sim") || arch == "x86_64";
            let sdk = if simulator {
                "iphonesimulator"
            } else {
                "iphoneos"
            };
            let sdk_path = Command::new("xcrun")
                .args(["--sdk", sdk, "--show-sdk-path"])
                .output()
                .ok()
                .filter(|output| output.status.success())
                .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
                .expect("the iOS SDK (xcrun --show-sdk-path)");
            let suffix = if simulator { "-simulator" } else { "" };
            Some(format!(
                "-target {clang_arch}-apple-ios{}{suffix} -isysroot {sdk_path}",
                version("IPHONEOS_DEPLOYMENT_TARGET", "15.0")
            ))
        }
        _ => None,
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
