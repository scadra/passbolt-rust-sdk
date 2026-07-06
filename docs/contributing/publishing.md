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
`crates/passbolt-ffi/pyproject.toml`.

Go and SwiftPM install from a Git repository rather than a registry: a release commits the package
to its repository and tags it, with the secret `SDK_REPOSITORIES_TOKEN`.

| Variable | Repository (variable to change it) | Tag |
|---|---|---|
| `PUBLISH_GO` | `scadra/passbolt-sdk-go` (`GO_REPOSITORY`): the module, static libraries included | `v<version>` |
| `PUBLISH_SWIFT` | `scadra/passbolt-sdk-swift` (`SWIFT_REPOSITORY`): `Package.swift` and the bindings; the XCFramework stays in the release, `Package.swift` naming its URL and checksum | `<version>` |

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
- **Go and Swift repositories**: two repositories, and a fine-grained personal access token with
  "Contents: read and write" on both, as `SDK_REPOSITORIES_TOKEN`.
- **crates.io**: a verified e-mail, and an API token with the `publish-new` and `publish-update`
  scopes for `switch-case-passbolt-*`. Once the crates exist, Trusted Publishing can replace it.

A publication is final on most registries: a version can be yanked or unlisted, not replaced.

## Releasing

The tag names the version: on a `vX.Y.Z` tag, `scripts/set-version.sh` gives every crate the version
`X.Y.Z` in the CI's checkout, so the packages, the CLI's `--version` and the crates.io upload carry it.
The versions in the `Cargo.toml` files only name the builds that are not releases.

```bash
git fetch origin
git tag -a v0.1.2 origin/master -m "passbolt-rust-sdk 0.1.2"
git push origin v0.1.2
```

A first job checks the tag has the `vX.Y.Z` form; the packages then go to each enabled registry, and
the payload to a GitHub release. A version a registry already holds is refused there: each release
needs a version none of them has published.

An annotated tag carries the date `GIT_COMMITTER_DATE` gives it; the GitHub release and the
registries keep the date they were published at.
