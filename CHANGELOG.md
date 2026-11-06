# Change Log
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased]
### Added
- LICENSE (AGPL-3.0), SECURITY.md, CONTRIBUTING.md and GitHub issue / pull request templates
- Passbolt license header on every Rust source file, checked by `scripts/license-headers.sh`
- SDK integration tests against an in-memory Passbolt API (`crates/passbolt-sdk/tests/it`)

### Changed
- Crate license changed from MIT to AGPL-3.0-or-later
- README follows the Passbolt repositories layout (license, about, contributing, credits)
- JavaScript SDK: methods with optional arguments take an options object (`listResourceViews({ search,
  withSecrets })`, `createUser({ username, firstName, lastName })`, `shareResource(id, { userIds,
  permissionType })`…), parameters are camelCase, errors are `PassboltError`s with a `code`
  (`isPassboltError`), `checkPasswordPwned` returns a `number`, and each session has its own
  `csrfTokenProvider`
- Go module: package `passbolt` (it was `passbolt_ffi`), formatted with gofmt, and
  `PassboltClient.Close` for a `defer client.Close()`
- NuGet package: its types are public (they were all `internal`), the native libraries sit under
  `runtimes/<rid>/native` once, with the XML documentation and a readme
- Java jar: records are Java records, automatic module name `com.passbolt.sdk`
- Swift package: module `PassboltSDK` over `PassboltSDKFFI`, macOS 12, `Codable` records and errors
  with the Rust messages; the release assets are `PassboltSDK-<version>.zip` and
  `PassboltSDKFFI.xcframework.zip`
- Android AAR: the system cleaner frees the native objects from API 34
- Python package: `import passbolt`, with `passbolt.Client` (keyword options, `with`, views as
  dicts) and error classes under `passbolt.PassboltError`
- Ruby gem: `require "passbolt"`, with `Passbolt::Client` (keyword options, a block that logs out)
  and `rescue Passbolt::Error`; `require "passbolt_sdk"` still works
