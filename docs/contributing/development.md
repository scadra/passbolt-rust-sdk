---
title: Development
sidebar_position: 1
---

# Development

Build the workspace, run the checks and the tests, and preview the documentation.

## Prerequisites

- Rust 1.88 or later, the `rust-version` of the crates.
- Node, for the WebAssembly tests, the OpenPGP.js interoperability tests and the documentation
  site.

## Workspace

| Crate | Content |
|---|---|
| `crates/passbolt-sdk` | The library: HTTP-agnostic client, GPGAuth, OpenPGP, metadata v5 |
| `crates/passbolt-cli` | The `passbolt` binary |
| `crates/passbolt-ffi` | UniFFI bindings (Python, Kotlin, Swift, Ruby, Go, C#, Java) |
| `crates/passbolt-wasm` | wasm-bindgen bindings (JavaScript, TypeScript) |

See [architecture](architecture.md) for how they fit together.

## Build and check

```bash
cargo build --release
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
bash scripts/license-headers.sh   # every .rs file must carry the Passbolt license header
```

`bash scripts/license-headers.sh --fix` adds the header where it is missing.

`passbolt-wasm` also builds for `wasm32-unknown-unknown`:

```bash
cargo clippy -p passbolt-wasm --target wasm32-unknown-unknown --all-targets -- -D warnings
cargo test -p passbolt-wasm --target wasm32-unknown-unknown   # in Node
```

The test needs Node and the `wasm-bindgen-test-runner` of the `wasm-bindgen` version in
`Cargo.lock`:

```bash
cargo install wasm-bindgen-cli --version <VERSION>
```

:::caution
In a container whose checkout is a folder shared with the host (Docker on macOS), the build may
read an older version of files that just changed: `can't find crate` errors, or tests of code that
is not there any more. Build with a target folder inside the container, and start it afresh when
that happens: `CARGO_TARGET_DIR=/tmp/passbolt-target cargo test --workspace`.
:::

## Tests

`cargo test` runs everything that needs no server:

| Level | Location | Against |
|---|---|---|
| Unit | `crates/*/src` (`#[cfg(test)]`) | Single functions |
| SDK integration | `crates/passbolt-sdk/tests/it` | An in-memory fake Passbolt API, data in `tests/fixtures` |
| CLI | `crates/passbolt-cli/tests/cli_test.rs` | The `passbolt` binary, offline |
| FFI | `crates/passbolt-ffi/tests/session.rs` | A wiremock server answering GPGAuth |
| WASM | `crates/passbolt-wasm/tests/session.rs` | A fake `fetch` setting cookies as Passbolt does (wasm32 only) |

Known bugs are `#[ignore]`d tests naming their ticket. List them with `cargo test -- --ignored`.

Run the interoperability tests with OpenPGP.js, which need Node:

```bash
npm ci --prefix tests/interop
cargo test -p passbolt-sdk --features interop --test it interop
```

## Run the end-to-end tests

`scripts/e2e.sh` runs the CLI against a real Passbolt server (`crates/passbolt-cli/tests/e2e`).

### 1. Prepare the server

The server needs:

- a user and an admin account, both without MFA;
- a second user to share with;
- v4 resource creation allowed.

### 2. Write the settings

```bash
cp .env.e2e.example .env.e2e   # then adapt it; .env.e2e is git-ignored
```

### 3. Run the tests

```bash
scripts/e2e.sh                                  # release build, 4 tests in parallel
E2E_THREADS=1 scripts/e2e.sh created_resource   # one test, sequentially
```

The script installs the OpenPGP.js of `tests/interop`, which checks what the CLI stores. It then
runs the `migrate-metadata` tests (`crates/passbolt-cli/tests/e2e_migration`) alone, after the others, since they
upgrade every v4 resource of the server.

Every test creates uniquely named data and deletes it, even when it fails.

## Preview the documentation

`docs/` is written for [Docusaurus](https://docusaurus.io) and reads as-is on GitHub. Besides its
`README.md`, each folder has a `_category_.json`: its label and position in the sidebar. See
[Writing the docs](docs-style.md) for the layout of a page, links, callouts and diagrams.

`website/` builds the site from `docs/`. `.github/workflows/docs.yml` builds it on each change, a
broken link or anchor failing the build, and publishes it to GitHub Pages from `master`.

Preview a change:

```bash
cd website
npm ci
npm start          # http://localhost:3000, reloaded on each save
npm run build      # what the CI checks
```

## Next steps

- [Architecture](architecture.md): the crates, a request's path, adding a method.
- [Bindings and CI](bindings-and-ci.md): the workflows and the packages.
- [Writing the docs](docs-style.md): the style of these pages.
