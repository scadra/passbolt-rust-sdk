---
title: Publishing
sidebar_position: 3
---

# Publishing

A `v<version>` tag, the version of `passbolt-ffi`, publishes the packages `sdk.yml` built and tested,
on each registry whose repository variable is `true` (Settings → Secrets and variables → Actions):

| Variable | Registry, package | Secrets |
|---|---|---|
| `PUBLISH_NPM` | npm `@switch-case/passbolt-sdk` | `NPM_TOKEN` |
| `PUBLISH_PYPI` | PyPI `switch-case-passbolt-sdk` | none: Trusted Publishing, workflow `sdk.yml`, environment `pypi` |
| `PUBLISH_NUGET` | NuGet `SwitchCase.Passbolt.Sdk` | `NUGET_API_KEY` |
| `PUBLISH_RUBYGEMS` | RubyGems `switch-case-passbolt-sdk` | `RUBYGEMS_API_KEY` |
| `PUBLISH_MAVEN` | Maven Central `<MAVEN_GROUP>:passbolt-sdk`, `:passbolt-sdk-android` | `MAVEN_CENTRAL_USERNAME`, `MAVEN_CENTRAL_PASSWORD` (Central Portal token), `MAVEN_GPG_PRIVATE_KEY` (armored), `MAVEN_GPG_PASSPHRASE` |
| `PUBLISH_CRATES` | crates.io `<CRATES_PREFIX>-passbolt-sdk`, `-passbolt-cli` | `CARGO_REGISTRY_TOKEN` |

`MAVEN_GROUP` defaults to `io.github.scadra`, a namespace Central verifies through GitHub; `CRATES_PREFIX`
to `switch-case`. The package names of the other registries are in `packaging/` and
`crates/passbolt-ffi/pyproject.toml`. Go and Swift have no registry: their packages are a Git tag of a
repository holding the content of `passbolt-sdk-go-<version>.tar.gz` and of `Package.swift` with the
XCFramework.

## Before the first release

1. Create the accounts and reserve the names on each registry.
2. Add the secrets above and set `PUBLISH_<REGISTRY>` to `true` for each registry ready.
3. On pypi.org, add a trusted publisher: repository `scadra/passbolt-rust`, workflow `sdk.yml`,
   environment `pypi`.
4. On Maven Central, verify the namespace of `MAVEN_GROUP`; publish the public part of the GPG
   key to a key server.
5. Push a `v<version>` tag: a first job checks it names the SDK version.
