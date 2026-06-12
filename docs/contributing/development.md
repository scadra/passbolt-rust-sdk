---
title: Development
sidebar_position: 1
---

# Development

## Workspace

| Crate | |
|---|---|
| `crates/passbolt-sdk` | The library: HTTP-agnostic client, GPGAuth, OpenPGP, metadata v5 |
| `crates/passbolt-cli` | The `passbolt` binary |
| `crates/passbolt-ffi` | UniFFI bindings (Python, Kotlin, Swift, Ruby, Go, C#, Java) |
| `crates/passbolt-wasm` | wasm-bindgen bindings (JavaScript, TypeScript) |

## Build and check

```bash
cargo build --release
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
bash scripts/license-headers.sh   # every .rs file must carry the Passbolt license header
```

`passbolt-wasm` also builds for `wasm32-unknown-unknown`:

```bash
cargo clippy -p passbolt-wasm --target wasm32-unknown-unknown --all-targets -- -D warnings
cargo test -p passbolt-wasm --target wasm32-unknown-unknown   # in Node
```

The second needs Node and the `wasm-bindgen-test-runner` of the `wasm-bindgen` version in
`Cargo.lock` (`cargo install wasm-bindgen-cli --version <version>`).

In a container whose checkout is a folder shared with the host (Docker on macOS), the build may
read files that just changed in an older version: `can't find crate` errors, or tests of code
that is not there any more. Build with a target folder inside the container, and start it afresh
when that happens: `CARGO_TARGET_DIR=/tmp/passbolt-target cargo test --workspace`.

## Tests

`cargo test` runs everything that needs no server:

| Level | Location | Against |
|---|---|---|
| Unit | `crates/*/src` (`#[cfg(test)]`) | single functions |
| SDK integration | `crates/passbolt-sdk/tests/it` | in-memory fake Passbolt API, data in `tests/fixtures` |
| CLI | `crates/passbolt-cli/tests/cli_test.rs` | the `passbolt` binary, offline |
| FFI | `crates/passbolt-ffi/tests/session.rs` | a wiremock server answering GPGAuth |
| WASM | `crates/passbolt-wasm/tests/session.rs` | a fake `fetch` setting cookies as Passbolt does (wasm32 only) |

Known bugs are `#[ignore]`d tests naming their ticket: `cargo test -- --ignored` lists them.

The interoperability tests with OpenPGP.js need Node:

```bash
npm ci --prefix tests/interop
cargo test -p passbolt-sdk --features interop --test it interop
```

## End-to-end tests

`scripts/e2e.sh` runs the CLI against a real Passbolt server (`crates/passbolt-cli/tests/e2e`).

```bash
cp .env.e2e.example .env.e2e   # then adapt it; .env.e2e is git-ignored
scripts/e2e.sh                  # release build, 4 tests in parallel
E2E_THREADS=1 scripts/e2e.sh created_resource   # one test, sequentially
```

The server needs a user and an admin account without MFA, a second user to share with, and v4
resource creation allowed. Every test creates uniquely named data and deletes it, even when it
fails.

## Documentation

`docs/` is written for [Docusaurus](https://docusaurus.io) and reads as-is on GitHub: each page
starts with a front matter (`title`, `sidebar_position`), each folder has a `README.md` (its
index) and a `_category_.json` (its label and position in the sidebar). Link pages by their
relative `.md` path.
