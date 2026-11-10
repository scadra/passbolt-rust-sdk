---
title: Dependencies
sidebar_position: 4
---

# Dependencies

What the SDK, the bindings and the CLI are built on, with the versions of `Cargo.lock` and the
other lock files. Every license is permissive (MIT, Apache-2.0, Unlicense) or weak copyleft
(MPL-2.0 for UniFFI, LGPL-3.0 for OpenPGP.js), compatible with the AGPL-3.0 of the project.

`cargo tree -p <crate> -e normal --depth 1` lists them again; `cargo metadata` gives the
licenses and repositories of the whole tree, the indirect dependencies included.

## Rust crates

### passbolt-sdk

The OpenPGP.js engine (`openpgpjs` feature) brings `rquickjs` and the WebCrypto primitives
(`aes`, `aes-gcm`, `cbc`, `ctr`, `hkdf`, `sha2`); the `native` feature brings `reqwest` and
`tokio`; WebAssembly brings `wasm-bindgen`, `js-sys` and `send_wrapper`.

| Crate | Version | License | Role |
|---|---|---|---|
| [`aes`](https://github.com/RustCrypto/block-ciphers) | 0.8.4 | MIT OR Apache-2.0 | AES for the OpenPGP.js engine (WebCrypto) / KDBX 3.1 |
| [`aes-gcm`](https://github.com/RustCrypto/AEADs) | 0.10.3 | Apache-2.0 OR MIT | AES-GCM for the OpenPGP.js engine (WebCrypto) |
| [`base64`](https://github.com/marshallpierce/rust-base64) | 0.22.1 | MIT OR Apache-2.0 | Base64 |
| [`cbc`](https://github.com/RustCrypto/block-modes) | 0.1.2 | MIT OR Apache-2.0 | CBC mode: OpenPGP.js engine, KDBX 3.1 |
| [`chrono`](https://github.com/chronotope/chrono) | 0.4.44 | MIT OR Apache-2.0 | Dates (RFC 3339, expiry) |
| [`ctr`](https://github.com/RustCrypto/block-modes) | 0.9.2 | MIT OR Apache-2.0 | CTR mode for the OpenPGP.js engine |
| [`hex`](https://github.com/KokaKiwi/rust-hex) | 0.4.3 | MIT OR Apache-2.0 | Hexadecimal (fingerprints, SHA-1) |
| [`hkdf`](https://github.com/RustCrypto/KDFs) | 0.12.4 | MIT OR Apache-2.0 | HKDF for the OpenPGP.js engine |
| [`js-sys`](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/js-sys) | 0.3.91 | MIT OR Apache-2.0 | JavaScript objects (WebAssembly) |
| [`percent-encoding`](https://github.com/servo/rust-url) | 2.3.2 | MIT OR Apache-2.0 | URL encoding of API paths |
| [`pgp`](https://github.com/rpgp/rpgp) | 0.21.0 | MIT OR Apache-2.0 | OpenPGP (rPGP): keys, encryption, signatures |
| [`rand`](https://github.com/rust-random/rand) | 0.8.8 | MIT OR Apache-2.0 | Random numbers (OS generator) |
| [`regex-lite`](https://github.com/rust-lang/regex) | 0.1.9 | MIT OR Apache-2.0 | `pattern` of the resource type schemas |
| [`reqwest`](https://github.com/seanmonstar/reqwest) | 0.12.15 | MIT OR Apache-2.0 | HTTP client (native, rustls) |
| [`rquickjs`](https://github.com/DelSkayn/rquickjs) | 0.14.0 | MIT | QuickJS, for the embedded OpenPGP.js engine |
| [`secrecy`](https://github.com/iqlusioninc/crates/tree/main/secrecy) | 0.10.3 | Apache-2.0 OR MIT | Secrets that do not print |
| [`send_wrapper`](https://github.com/thk1/send_wrapper) | 0.6.0 | MIT OR Apache-2.0 | OpenPGP.js engine in WebAssembly |
| [`serde`](https://github.com/serde-rs/serde) | 1.0.228 | MIT OR Apache-2.0 | Serialization |
| [`serde_json`](https://github.com/serde-rs/json) | 1.0.149 | MIT OR Apache-2.0 | JSON |
| [`sha1`](https://github.com/RustCrypto/hashes) | 0.10.6 | MIT OR Apache-2.0 | Have I Been Pwned (k-anonymity) |
| [`sha2`](https://github.com/RustCrypto/hashes) | 0.10.9 | MIT OR Apache-2.0 | SHA-256: OpenPGP.js engine, KDBX |
| [`thiserror`](https://github.com/dtolnay/thiserror) | 2.0.18 | MIT OR Apache-2.0 | Error types |
| [`tokio`](https://github.com/tokio-rs/tokio) | 1.50.0 | MIT | Async runtime |
| [`totp-rs`](https://github.com/constantoine/totp-rs) | 5.7.0 | MIT | TOTP codes |
| [`unicode-segmentation`](https://github.com/unicode-rs/unicode-segmentation) | 1.12.0 | MIT OR Apache-2.0 | Characters as users see them (secret entropy) |
| [`url`](https://github.com/servo/rust-url) | 2.5.8 | MIT OR Apache-2.0 | URLs |
| [`uuid`](https://github.com/uuid-rs/uuid) | 1.26.1 | Apache-2.0 OR MIT | UUIDs |
| [`wasm-bindgen`](https://github.com/wasm-bindgen/wasm-bindgen) | 0.2.114 | MIT OR Apache-2.0 | Rust ↔ JavaScript |
| [`wasm-bindgen-futures`](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/futures) | 0.4.64 | MIT OR Apache-2.0 | Promises ↔ futures |
| [`zeroize`](https://github.com/RustCrypto/utils) | 1.8.2 | Apache-2.0 OR MIT | Secrets zeroed in memory |

### passbolt-ffi

| Crate | Version | License | Role |
|---|---|---|---|
| [`chrono`](https://github.com/chronotope/chrono) | 0.4.44 | MIT OR Apache-2.0 | Dates (RFC 3339, expiry) |
| [`secrecy`](https://github.com/iqlusioninc/crates/tree/main/secrecy) | 0.10.3 | Apache-2.0 OR MIT | Secrets that do not print |
| [`serde`](https://github.com/serde-rs/serde) | 1.0.228 | MIT OR Apache-2.0 | Serialization |
| [`serde_json`](https://github.com/serde-rs/json) | 1.0.149 | MIT OR Apache-2.0 | JSON |
| [`tokio`](https://github.com/tokio-rs/tokio) | 1.50.0 | MIT | Async runtime |
| [`uniffi`](https://github.com/mozilla/uniffi-rs) | 0.29.5 | MPL-2.0 | FFI bindings generator (Mozilla) |

### passbolt-wasm

| Crate | Version | License | Role |
|---|---|---|---|
| [`getrandom`](https://github.com/rust-random/getrandom) | 0.2.17 | MIT OR Apache-2.0 | Randomness from the Web Crypto API |
| [`js-sys`](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/js-sys) | 0.3.91 | MIT OR Apache-2.0 | JavaScript objects (WebAssembly) |
| [`secrecy`](https://github.com/iqlusioninc/crates/tree/main/secrecy) | 0.10.3 | Apache-2.0 OR MIT | Secrets that do not print |
| [`serde`](https://github.com/serde-rs/serde) | 1.0.228 | MIT OR Apache-2.0 | Serialization |
| [`serde-wasm-bindgen`](https://github.com/RReverser/serde-wasm-bindgen) | 0.6.5 | MIT | Serde ↔ JavaScript values |
| [`serde_json`](https://github.com/serde-rs/json) | 1.0.149 | MIT OR Apache-2.0 | JSON |
| [`uuid`](https://github.com/uuid-rs/uuid) | 1.26.1 | Apache-2.0 OR MIT | UUIDs |
| [`wasm-bindgen`](https://github.com/wasm-bindgen/wasm-bindgen) | 0.2.114 | MIT OR Apache-2.0 | Rust ↔ JavaScript |
| [`wasm-bindgen-futures`](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/futures) | 0.4.64 | MIT OR Apache-2.0 | Promises ↔ futures |
| [`web-sys`](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/web-sys) | 0.3.91 | MIT OR Apache-2.0 | Web APIs (`fetch`) |

### passbolt-cli

`ratatui` and `arboard` come with the `tui` feature, on by default.

| Crate | Version | License | Role |
|---|---|---|---|
| [`aes`](https://github.com/RustCrypto/block-ciphers) | 0.8.4 | MIT OR Apache-2.0 | AES for the OpenPGP.js engine (WebCrypto) / KDBX 3.1 |
| [`anyhow`](https://github.com/dtolnay/anyhow) | 1.0.102 | MIT OR Apache-2.0 | Errors of the CLI |
| [`arboard`](https://github.com/1Password/arboard) | 3.7.0 | MIT OR Apache-2.0 | System clipboard (`tui`) |
| [`argon2`](https://github.com/RustCrypto/password-hashes/tree/master/argon2) | 0.5.3 | MIT OR Apache-2.0 | Argon2 KDF (KDBX 4 import) |
| [`base64`](https://github.com/marshallpierce/rust-base64) | 0.22.1 | MIT OR Apache-2.0 | Base64 |
| [`cbc`](https://github.com/RustCrypto/block-modes) | 0.1.2 | MIT OR Apache-2.0 | CBC mode: OpenPGP.js engine, KDBX 3.1 |
| [`cel`](https://github.com/cel-rust/cel-rust) | 0.15.0 | MIT | CEL `--filter` expressions |
| [`chacha20`](https://github.com/RustCrypto/stream-ciphers) | 0.9.1 | Apache-2.0 OR MIT | ChaCha20 (KDBX 4) |
| [`chrono`](https://github.com/chronotope/chrono) | 0.4.44 | MIT OR Apache-2.0 | Dates (RFC 3339, expiry) |
| [`clap`](https://github.com/clap-rs/clap) | 4.5.60 | MIT OR Apache-2.0 | Command line |
| [`clap_complete`](https://github.com/clap-rs/clap) | 4.5.66 | MIT OR Apache-2.0 | Shell completions |
| [`clap_mangen`](https://github.com/clap-rs/clap) | 0.2.31 | MIT OR Apache-2.0 | Man pages (`gendoc`) |
| [`config`](https://github.com/rust-cli/config-rs) | 0.14.1 | MIT OR Apache-2.0 | Config files (TOML, YAML, JSON) |
| [`directories`](https://github.com/soc/directories-rs) | 5.0.1 | MIT OR Apache-2.0 | Config directory of each OS |
| [`flate2`](https://github.com/rust-lang/flate2-rs) | 1.1.9 | MIT OR Apache-2.0 | Gzip (KDBX) |
| [`hmac`](https://github.com/RustCrypto/MACs) | 0.12.1 | MIT OR Apache-2.0 | HMAC (KDBX 4) |
| [`indicatif`](https://github.com/console-rs/indicatif) | 0.17.11 | MIT | Progress bars |
| [`keepass`](https://github.com/sseemayer/keepass-rs) | 0.6.19 | MIT | KDBX read and KDBX 4 write |
| [`rand`](https://github.com/rust-random/rand) | 0.8.8 | MIT OR Apache-2.0 | Random numbers (OS generator) |
| [`ratatui`](https://github.com/ratatui/ratatui) | 0.29.0 | MIT | Terminal UI (`tui`), with crossterm |
| [`rpassword`](https://github.com/conradkleinespel/rpassword) | 7.4.0 | Apache-2.0 | Hidden password prompt |
| [`salsa20`](https://github.com/RustCrypto/stream-ciphers) | 0.10.2 | MIT OR Apache-2.0 | Salsa20 (KDBX 3.1 protected fields) |
| [`secrecy`](https://github.com/iqlusioninc/crates/tree/main/secrecy) | 0.10.3 | Apache-2.0 OR MIT | Secrets that do not print |
| [`secstr`](https://codeberg.org/valpackett/secstr) | 0.5.1 | Unlicense | Secret strings of the keepass crate |
| [`serde`](https://github.com/serde-rs/serde) | 1.0.228 | MIT OR Apache-2.0 | Serialization |
| [`serde_json`](https://github.com/serde-rs/json) | 1.0.149 | MIT OR Apache-2.0 | JSON |
| [`sha2`](https://github.com/RustCrypto/hashes) | 0.10.9 | MIT OR Apache-2.0 | SHA-256: OpenPGP.js engine, KDBX |
| [`tokio`](https://github.com/tokio-rs/tokio) | 1.50.0 | MIT | Async runtime |
| [`toml`](https://github.com/toml-rs/toml) | 0.8.23 | MIT OR Apache-2.0 | TOML |
| [`unicode-width`](https://github.com/unicode-rs/unicode-width) | 0.2.0 | MIT OR Apache-2.0 | Column widths of tables |
| [`xml-rs`](https://github.com/kornelski/xml-rs) | 0.8.28 | MIT | KDBX XML |
| [`zeroize`](https://github.com/RustCrypto/utils) | 1.8.2 | Apache-2.0 OR MIT | Secrets zeroed in memory |

### Tests only

| Crate | Used by |
|---|---|
| [`assert_cmd`](https://github.com/assert-rs/assert_cmd) | `passbolt-cli` |
| [`futures-executor`](https://github.com/rust-lang/futures-rs) | `passbolt-sdk`, `passbolt-ffi`, `passbolt-wasm` |
| [`predicates`](https://github.com/assert-rs/predicates-rs) | `passbolt-cli` |
| [`proptest`](https://github.com/proptest-rs/proptest) | `passbolt-sdk` |
| [`rstest`](https://github.com/la10736/rstest) | `passbolt-sdk`, `passbolt-ffi`, `passbolt-wasm`, `passbolt-cli` |
| [`tempfile`](https://github.com/Stebalien/tempfile) | `passbolt-cli` |
| [`tokio-test`](https://github.com/tokio-rs/tokio) | `passbolt-cli` |
| [`totp-rs`](https://github.com/constantoine/totp-rs) | `passbolt-cli` |
| [`url`](https://github.com/servo/rust-url) | `passbolt-ffi` |
| [`uuid`](https://github.com/uuid-rs/uuid) | `passbolt-ffi` |
| [`wasm-bindgen-test`](https://github.com/wasm-bindgen/wasm-bindgen) | `passbolt-wasm` |
| [`wiremock`](https://github.com/LukeMathWalker/wiremock-rs) | `passbolt-sdk`, `passbolt-ffi` |

## Shipped with the SDK

| Component | Version | License | Where |
|---|---|---|---|
| [OpenPGP.js](https://github.com/openpgpjs/openpgpjs) | 6.1.1 | LGPL-3.0-or-later | `crates/passbolt-sdk/vendor/openpgpjs`, the `openpgpjs` engine; `tests/interop` checks what rPGP writes with it |
| [EFF large wordlist](https://www.eff.org/dice) | 2016 | CC BY 3.0 US | `crates/passbolt-sdk/src/generator/words.txt`, the passphrases, as in the browser extension |
| [GopenPGP](https://github.com/ProtonMail/gopenpgp) | 3.5.2 | MIT | `crates/passbolt-sdk/gopenpgp`, the optional `gopenpgp` engine (needs Go) |
| [JNA](https://github.com/java-native-access/jna) | 5.14.0 | Apache-2.0 OR LGPL-2.1 | Java and Android bindings: calls the native library |
| [kotlinx.coroutines](https://github.com/Kotlin/kotlinx.coroutines) | 1.9.0 | Apache-2.0 | Android: the `suspend` functions of `AsyncPassboltClient` |
| [ffi](https://github.com/ffi/ffi) (gem) | ~> 1.15 | BSD-3-Clause | Ruby bindings: calls the native library |

## Build and packaging

| Tool | Version | Builds |
|---|---|---|
| [Rust](https://github.com/rust-lang/rust) | 1.88 or later | everything (`rust-version` of the crates) |
| [UniFFI](https://github.com/mozilla/uniffi-rs) `uniffi-bindgen` | 0.29.5 | Python, Kotlin, Swift and Ruby bindings |
| [uniffi-bindgen-go](https://github.com/NordSecurity/uniffi-bindgen-go) | 0.5.0+v0.29.5 | Go bindings |
| [uniffi-bindgen-cs](https://github.com/NordSecurity/uniffi-bindgen-cs) | 0.10.0+v0.29.4 | C# bindings |
| [uniffi-bindgen-java](https://github.com/IronCoreLabs/uniffi-bindgen-java) | 0.2.1 | Java bindings |
| [wasm-bindgen-cli](https://github.com/wasm-bindgen/wasm-bindgen) | as `Cargo.lock` (0.2.114) | the npm package |
| [TypeScript](https://github.com/microsoft/TypeScript) | 5.8.3 | checks the declarations of the npm package |
| [maturin](https://github.com/PyO3/maturin) | 1.8 or later | Python wheels |
| [cargo-ndk](https://github.com/bbqsrc/cargo-ndk) | 4.1.2 | Android libraries |
| [Gradle](https://github.com/gradle/gradle) | 8.11.1 | Android AAR, with the [Android Gradle plugin](https://developer.android.com/build) 8.7.3 and [Kotlin](https://github.com/JetBrains/kotlin) 2.1.0 |
| [Swift](https://github.com/swiftlang/swift) | tools 5.9 | Swift package and XCFramework |
| [.NET](https://github.com/dotnet/runtime) | 8 | NuGet package |
| [Go](https://github.com/golang/go) | stable | Go module (cgo), the `gopenpgp` engine |
| [Docusaurus](https://github.com/facebook/docusaurus) | 3.9.2 | this documentation (`website/`), with React 18.3.1 |
| [gitleaks](https://github.com/gitleaks/gitleaks) | 8.24.0 | the secret scan of the CI |

## GitHub Actions

`ci.yml`, `sdk.yml` and `docs.yml` use
[actions/checkout](https://github.com/actions/checkout),
[actions/cache](https://github.com/actions/cache),
[actions/upload-artifact](https://github.com/actions/upload-artifact) and
[download-artifact](https://github.com/actions/download-artifact),
[actions/setup-node](https://github.com/actions/setup-node),
[setup-python](https://github.com/actions/setup-python),
[setup-java](https://github.com/actions/setup-java),
[setup-go](https://github.com/actions/setup-go),
[setup-dotnet](https://github.com/actions/setup-dotnet),
[actions/upload-pages-artifact](https://github.com/actions/upload-pages-artifact) and
[deploy-pages](https://github.com/actions/deploy-pages),
[dtolnay/rust-toolchain](https://github.com/dtolnay/rust-toolchain),
[Swatinem/rust-cache](https://github.com/Swatinem/rust-cache),
[PyO3/maturin-action](https://github.com/PyO3/maturin-action),
[ruby/setup-ruby](https://github.com/ruby/setup-ruby),
[gradle/actions](https://github.com/gradle/actions),
[NuGet/login](https://github.com/NuGet/login),
[pypa/gh-action-pypi-publish](https://github.com/pypa/gh-action-pypi-publish) and
[rubygems/configure-rubygems-credentials](https://github.com/rubygems/configure-rubygems-credentials).

## Adding one

A new dependency needs a reason the standard library or a crate already there cannot give, a
license from the list above, and a maintained repository. Prefer pure Rust (the musl and
WebAssembly builds), and leave optional what only one feature uses, as `tui` does.
