---
title: Bindings and CI
sidebar_position: 2
---

# Bindings and CI

Generate the language bindings, build and test the packages, and know what each workflow checks.

## Workflows

| Workflow | Runs on | What it does |
|---|---|---|
| `.github/workflows/ci.yml` | Each push to `master` and each pull request | Formatting, clippy, tests (workspace, wasm32, OpenPGP.js interop), a build with the minimum Rust version, and a gitleaks scan. |
| `.github/workflows/sdk.yml` | Each push to `master`, each `v*` tag, a manual run, and the pull requests that change it (see below) | The CLI for each platform and the SDK packages (JS/TS, Python, Java, Go, .NET, Ruby, iOS, Android), each with a smoke test, in one `passbolt-<version>` artifact with a `SHA256SUMS`. |
| `.github/workflows/docs.yml` | Each push to `master` and each pull request that changes `docs/`, `website/` or the workflow, and a manual run | Builds the documentation site and publishes it from `master`. See [development](development.md#preview-the-documentation). |

On a pull request, `sdk.yml` runs when it changes `passbolt-ffi`, `passbolt-wasm`, `packaging/`,
`scripts/sdk-bindings.sh`, `docs/sdk/go.md`, `docs/sdk/java.md`, `docs/sdk/javascript.md` or the
workflow itself.

A `v*` tag makes the `sdk.yml` artifact a GitHub release and [publishes](publishing.md) the
packages.

## Generate the FFI bindings

```bash
cargo build --release -p passbolt-ffi --lib
bash scripts/sdk-bindings.sh target/release/libpassbolt_ffi.so bindings [language...]
```

The script takes the library (`.so` or `.dylib`), an output folder, and the languages to
generate, all of them when none is given:

| Language | Generator |
|---|---|
| `python`, `kotlin`, `swift`, `ruby` | The crate's own `uniffi-bindgen`, at the UniFFI version of `Cargo.lock` |
| `go`, `csharp`, `java` | Their generators on the `PATH`, at the versions `sdk.yml` pins, matching the UniFFI of `Cargo.lock` |

Package names come from `crates/passbolt-ffi/uniffi.toml`.

:::caution
The generators read the UniFFI metadata symbols of the library. A stripped library has none, and
the generators then write nothing, without an error. The release profile strips, so `sdk.yml`
builds the SDK library with `CARGO_PROFILE_RELEASE_STRIP=false`, and the script fails when a
language comes out empty.
:::

## Keep the two clients in step

`crates/passbolt-ffi/src/lib.rs` lists each method once, in `client_methods!`, with an async
body. The macro makes two methods from it:

- the blocking `PassboltClient` method, which waits on the FFI runtime;
- the `AsyncPassboltClient` method, which spawns the body on that runtime and awaits it from the
  caller's executor.

Add a method to the list, not to one of the `impl` blocks, so that both clients keep the same
API. `rustfmt` does not format the list.

Two languages drop the async client:

- The Ruby generator of UniFFI 0.29 has no async support: `packaging/ruby/passbolt.rb` removes
  `AsyncPassboltClient`.
- uniffi-bindgen-go makes its methods blocking: `packaging/go/rename` unexports it.

## Packaging

| Package | Built from |
|---|---|
| npm | `packaging/js/` and the `bundler` and `nodejs` builds of `wasm-bindgen` |
| Python wheels | `crates/passbolt-ffi/pyproject.toml` and the `passbolt` package of `crates/passbolt-ffi/python/`, with maturin |
| Java jar | The Java bindings, the libraries under JNA's `<os>-<arch>/` resource folders |
| Android AAR | `packaging/android/` (Gradle), the libraries of `cargo ndk` |
| NuGet | `packaging/dotnet/`, the libraries under `runtimes/<rid>/native` |
| Ruby gem | `packaging/ruby/`, the libraries under `lib/native/<os>-<arch>/` |
| Go module | The Go bindings as package `passbolt`, given Go names by `packaging/go/rename`, the hand-written `packaging/go/*.go`, the static libraries and their cgo link flags |
| Swift package | `packaging/swift/Package.swift`, an XCFramework for devices and simulators |

## Smoke-test the packages

The smoke tests in `packaging/smoke/` install each package and call it: the library loads, and a
Rust error reaches the language as its own error.

- TypeScript: `smoke.ts` is also compiled with `tsc --strict` against the installed npm package.
- Go: `smoke.go` and the blocks of `docs/sdk/go.md` (`packaging/go/docexamples`) pass `go vet`
  against the module.

## Keep the TypeScript types in step

The objects the JavaScript session takes and returns are declared in
`crates/passbolt-wasm/src/types.d.ts`, from the SDK structures as serde serializes them:

- an `Option` not skipped is `T | null`;
- a field skipped when empty is optional;
- a date is an RFC 3339 `string`.

Each method names its types with `unchecked_return_type` and `unchecked_param_type`.

A change to a serialized SDK structure needs the same change there, and the CI checks it. The
`typescript_samples` example prints the SDK fixtures, serialized as the session returns them and
typed with these declarations; `tsc --strict` refuses a missing field, an unknown one or a wrong
type. Run the check locally:

```bash
mkdir -p /tmp/types
cargo run -q -p passbolt-wasm --example typescript_samples > /tmp/types/samples.ts
cp crates/passbolt-wasm/src/types.d.ts /tmp/types/
npx tsc --strict --noEmit --target es2022 --module nodenext /tmp/types/samples.ts
```

## Related

- [Publishing](publishing.md): release the packages to the registries.
- [Architecture](architecture.md#add-a-method-end-to-end): add a method to every binding.
- [Dependencies](dependencies.md): the generator and tool versions.
