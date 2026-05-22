---
title: Bindings and CI
sidebar_position: 2
---

# Bindings and CI

## Workflows

- `.github/workflows/ci.yml`: formatting, clippy, tests (workspace, wasm32, OpenPGP.js interop),
  a build with the minimum Rust version, and a gitleaks scan.
- `.github/workflows/sdk.yml`: the CLI for each platform and the SDK packages (JS/TS, Python,
  Java, Go, .NET, Ruby, iOS, Android), each with a smoke test, in one `passbolt-<version>`
  artifact with a `SHA256SUMS`. A `v*` tag makes it a GitHub release and
  [publishes](publishing.md) the packages. A change to `passbolt-ffi`, `passbolt-wasm`,
  `packaging/` or the workflow runs it on the pull request.

## Generating the FFI bindings

```bash
cargo build --release -p passbolt-ffi --lib
bash scripts/sdk-bindings.sh target/release/libpassbolt_ffi.so bindings [language...]
```

Languages: `python`, `kotlin`, `swift`, `ruby` (the crate's own `uniffi-bindgen`), `go`, `csharp`,
`java` (their generators on the `PATH`, at the versions `sdk.yml` pins, matching the UniFFI of
`Cargo.lock`). Package names come from `crates/passbolt-ffi/uniffi.toml`.

The generators read the UniFFI metadata symbols of the library. A stripped library has none, and
they then write nothing without an error: the release profile strips, so `sdk.yml` builds the
SDK library with `CARGO_PROFILE_RELEASE_STRIP=false`, and the script fails when a language comes
out empty.

## Packaging

| Package | Built from |
|---|---|
| npm | `packaging/js/` and the `bundler` and `nodejs` builds of `wasm-bindgen` |
| Python wheels | `crates/passbolt-ffi/pyproject.toml`, with maturin |
| Java jar | the Java bindings, the libraries under JNA's `<os>-<arch>/` resource folders |
| Android AAR | `packaging/android/` (Gradle), the libraries of `cargo ndk` |
| NuGet | `packaging/dotnet/`, the libraries under `runtimes/<rid>/native` |
| Ruby gem | `packaging/ruby/`, the libraries under `lib/native/<os>-<arch>/` |
| Go module | the Go bindings, the static libraries and their cgo link flags |
| Swift package | `packaging/swift/Package.swift`, an XCFramework for devices and simulators |

The smoke tests in `packaging/smoke/` install each package and call it: the library loads and a
Rust error reaches the language as its own error.
