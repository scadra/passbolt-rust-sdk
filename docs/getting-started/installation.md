---
title: Installation
sidebar_position: 1
---

# Installation

## The CLI

### From a release

Each release ships the `passbolt` binary for Linux (x86_64, aarch64, static musl), macOS (Intel,
Apple silicon) and Windows (a `.zip`), with a `SHA256SUMS` file. Download the archive of your
platform, check it, and put `passbolt` on your `PATH`:

```bash
sha256sum --check --ignore-missing SHA256SUMS
tar xzf passbolt-cli-<version>-x86_64-unknown-linux-gnu.tar.gz
sudo install passbolt-cli-<version>-x86_64-unknown-linux-gnu/passbolt /usr/local/bin/
```

### From source

Rust 1.88 or later; no OpenSSL needed.

```bash
git clone https://github.com/scadra/passbolt-rust-sdk.git
cd passbolt-rust-sdk
cargo build --release
sudo install target/release/passbolt /usr/local/bin/
```

Check it runs:

```bash
passbolt --version
```

### Shell completion

```bash
passbolt completion bash   >> ~/.bashrc
passbolt completion zsh    >> ~/.zshrc
passbolt completion fish   > ~/.config/fish/completions/passbolt.fish
passbolt completion powershell
```

## The SDK

The SDK packages are built by the CI for each release. The names below are those of the proof of
concept; each [language page](../sdk/README.md) tells how to use them.

| Language | Package |
|---|---|
| Rust | crates.io `switch-case-passbolt-sdk` (imported as `passbolt_sdk`) |
| JavaScript / TypeScript | npm `@switch-case/passbolt-sdk` |
| Python | PyPI `switch-case-passbolt-sdk` (imported as `passbolt_ffi`) |
| Java | Maven `io.github.scadra:passbolt-sdk` |
| Android | Maven `io.github.scadra:passbolt-sdk-android` (AAR) |
| .NET | NuGet `SwitchCase.Passbolt.Sdk` |
| Ruby | RubyGems `switch-case-passbolt-sdk` |
| Go | `passbolt-sdk-go-<version>.tar.gz` of the release |
| Swift (iOS) | `PassboltSDK-ios-<version>.zip` of the release (Swift package and XCFramework) |
