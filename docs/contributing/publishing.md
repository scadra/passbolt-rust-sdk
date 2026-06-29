---
title: Publishing
sidebar_position: 3
---

# Publishing

A `v<version>` tag, the version of `passbolt-ffi`, publishes the packages `sdk.yml` built and tested,
on each registry whose repository variable is `true` (Settings → Secrets and variables → Actions).
A registry without its variable is skipped.

| Variable | Registry, package | Credentials |
|---|---|---|
| `PUBLISH_NPM` | npm `@switch-case/passbolt-sdk` | secret `NPM_TOKEN` |
| `PUBLISH_PYPI` | PyPI `switch-case-passbolt-sdk` | Trusted Publishing, environment `pypi` |
| `PUBLISH_NUGET` | NuGet `SwitchCase.Passbolt.Sdk` | Trusted Publishing, environment `nuget`, variable `NUGET_USER` |
| `PUBLISH_RUBYGEMS` | RubyGems `switch-case-passbolt-sdk` | Trusted Publishing, environment `rubygems` |
| `PUBLISH_MAVEN` | Maven Central `<MAVEN_GROUP>:passbolt-sdk`, `:passbolt-sdk-android` | secrets `MAVEN_CENTRAL_USERNAME`, `MAVEN_CENTRAL_PASSWORD` (Central Portal token), `MAVEN_GPG_PRIVATE_KEY` (armored), `MAVEN_GPG_PASSPHRASE` |
| `PUBLISH_CRATES` | crates.io `<CRATES_PREFIX>-passbolt-sdk`, `-passbolt-cli` | secret `CARGO_REGISTRY_TOKEN` |

`MAVEN_GROUP` defaults to `io.github.scadra`, a namespace Central verifies through GitHub;
`CRATES_PREFIX` to `switch-case`. The package names of the other registries are in `packaging/` and
`crates/passbolt-ffi/pyproject.toml`. Go and Swift have no registry: their packages are a Git tag of a
repository holding the content of `passbolt-sdk-go-<version>.tar.gz` and of `Package.swift` with the
XCFramework.

## Setting up each registry

With Trusted Publishing, the registry trusts the workflow itself: no secret to keep or renew. Each
declares the same publisher: owner `scadra`, repository `passbolt-rust-sdk`, workflow `sdk.yml`, and
the environment of the table.

- **npm**: an organization `switch-case` (free plan), and a granular access token with read and
  write on it. `--provenance` requires the `repository` of `packaging/js/package.json` to name this
  repository.
- **PyPI**: an account with 2FA, and a pending publisher (Account → Publishing) for the project
  `switch-case-passbolt-sdk`.
- **NuGet**: a trusted publishing policy for the owner `switch-case`, scope "Push new packages and
  package versions", package `SwitchCase.Passbolt.Sdk`; `NUGET_USER` is the nuget.org profile
  name.
- **RubyGems**: an account with MFA, and a pending trusted publisher for the gem
  `switch-case-passbolt-sdk`.
- **Maven Central**: sign in to central.sonatype.com with GitHub, which verifies
  `io.github.scadra`; a user token; a GPG signing key, its public part sent to `keys.openpgp.org`.
- **crates.io**: a verified e-mail, and an API token with the `publish-new` and `publish-update`
  scopes for `switch-case-passbolt-*`. Once the crates exist, Trusted Publishing can replace it.

A publication is final on most registries: a version can be yanked or unlisted, not replaced.

## Releasing

```bash
git tag v0.1.0
git push origin v0.1.0
```

A first job checks the tag names the SDK version; the packages then go to each enabled registry,
and the payload to a GitHub release.
