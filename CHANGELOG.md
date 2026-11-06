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
