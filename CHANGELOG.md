# Change Log
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased]
### Added
- LICENSE (AGPL-3.0), SECURITY.md, CONTRIBUTING.md and GitHub issue / pull request templates
- Passbolt license header on every Rust source file, checked by `scripts/license-headers.sh`
- SDK integration tests against an in-memory Passbolt API (`crates/passbolt-sdk/tests/it`)
- Password generator of the browser extension in the SDK and every binding: passwords from its
  character sets, passphrases of its EFF word list, PIN codes, the password policies of the
  organization (`get_password_policies`, `save_password_policies`), and the entropy and strength
  it shows; in the CLI, `passbolt generate [password|passphrase|pin]` and `--generate` on
  `create resource` and `update resource`
- FFI bindings: `AsyncPassboltClient`, the methods of `PassboltClient` awaited in each
  language's own way: coroutines in Python (`passbolt.AsyncClient`, `async with`), `suspend` in
  Kotlin, `async` in Swift, `Task` in C#, `CompletableFuture` in Java; Go and Ruby keep the
  blocking client. The Android AAR now depends on kotlinx-coroutines

### Changed
- Crate license changed from MIT to AGPL-3.0-or-later
- README follows the Passbolt repositories layout (license, about, contributing, credits)
- JavaScript SDK: methods with optional arguments take an options object (`listResourceViews({ search,
  withSecrets })`, `createUser({ username, firstName, lastName })`, `shareResource(id, { userIds,
  permissionType })`…), parameters are camelCase, errors are `PassboltError`s with a `code`
  (`isPassboltError`), `checkPasswordPwned` returns a `number`, and each session has its own
  `csrfTokenProvider`
- FFI bindings (breaking): the types lose their `Ffi` prefix (`Resource`, `LoginOptions`,
  `PassboltError`, `PassboltException` in Kotlin, Java and .NET); resource views are
  `ResourceView` records and resources are written from `NewResource` and `ResourceChanges`
  records, no longer JSON text; optional arguments and record fields have defaults;
  `share_resource` and `share_folder` take the permission type before the users and groups;
  `login_with_options` is gone, `login_with_config` takes its options
- SDK and bindings (breaking): `logout` returns the error of the server instead of ignoring it;
  the CLI warns and goes on
- Go module (breaking): option structs for the calls with optional arguments (`ListResources(nil)`,
  `ShareResource(id, passbolt.Share{…})`), Go initialisms (`ID`, `URL`, `URIs`), the generated
  plumbing unexported, `Call` and `Run` to give up waiting on a `context.Context`, and `Close`
  returns the error of the logout
- Java jar: `NewResourceBuilder`, `ResourceChangesBuilder`, `LoginOptionsBuilder` and
  `TotpDataBuilder`, with the defaults of the records
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
