# Contributing to passbolt

## Introduction

Thank you for your interest in passbolt. We welcome contributions from everyone, this guide is here to help you get started!

### Code of Conduct

First things first, please read our [Code of Conduct](https://www.passbolt.com/code_of_conduct).
Help us keep Passbolt open and inclusive!

## High level guidelines

There are a few guidelines that we need contributors to follow so that we have a chance of keeping on top of things.

### Reporting a security Issue

If you've found a security related issue in Passbolt, please don't open an issue on GitHub. Follow our responsible disclosure process: https://www.passbolt.com/docs/contribute/security/vulnerability/.

### Reporting a bug
Please only use github for bugs or pull request.

* Make sure you have a [GitHub account](https://github.com/signup/free).
* Submit an issue on this repository
  * Check first that a similar issue does not already exist.
  * Make sure you fill in the earliest version that you know has the issue if it is a bug.
  * Clearly describe the issue including steps to reproduce the bug

### Requesting a new feature or ehancement

Please use the community forum: http://community.passbolt.com/
Do not use github to request new features.

### Getting help with an installation issue

Please use the community forum: http://community.passbolt.com/
Do not use github to request help with your instance installation.

### How can you help?

There are several ways you can help out:

* Create an issue on GitHub ONLY if you have found a bug
* Review [enhancement or new feature requests](https://community.passbolt.com/c/backlog) on the community foum and contribute to the functional or technical specifications in the issues.
* Fix a known bug: `cargo test -- --ignored` lists the ones with a failing test, each test names its ticket
* Contribute to the [documentation](https://passbolt.com/help).
* Write unit test cases to help increase test coverage.

If you have any suggestions or want to get involved in other ways feel free to get in touch with us at [contact@passbolt.com](mailto:contact@passbolt.com)!

### Making code changes

#### Which branch to base the work?

* Bugfix branches will be based on master.
* New features that are backwards compatible will be based on next minor release branch.
* New features or other non backwards compatible changes will go in the next major release branch.

#### Make changes locally first
* Fork the repository on GitHub.
* Create a feature branch from where you want to base your work.
  * This is usually the master branch.
  * Only target release branches if you are certain your fix must be on that
    branch.
  * To quickly create a feature branch based on master; `git branch
    feature/ID_feature_description master` then checkout the new branch with `git
    checkout feature/ID_feature_description`. Better avoid working directly on the
    `master` branch, to avoid conflicts if you pull in updates from origin.
* Make commits of logical units.

#### Before submiting changes
* Check for unnecessary whitespace with `git diff --check` before committing.
* Use descriptive commit messages and reference the #issue number.
* `cargo test --workspace` should continue to pass.
* `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --check` should not report anything.
* For `passbolt-wasm`: `cargo clippy -p passbolt-wasm --target wasm32-unknown-unknown -- -D warnings`, and
  `cargo test -p passbolt-wasm --target wasm32-unknown-unknown` runs its tests in Node; it needs Node and
  `wasm-bindgen-test-runner` of the `wasm-bindgen` version in `Cargo.lock`
  (`cargo install wasm-bindgen-cli --version <version>`).
* The CI (`.github/workflows/ci.yml`) runs all of the above, a build with the minimum Rust version and a
  gitleaks scan. The end-to-end tests need a Passbolt server: run them with `scripts/e2e.sh`.
* Every new `.rs` file must start with the Passbolt license header: run `bash scripts/license-headers.sh`
  (or `bash scripts/license-headers.sh --fix` to add it).
* Never log or print secrets (passphrases, private keys, decrypted secrets), even in `--debug` mode.
* `.github/workflows/sdk.yml` builds the CLI for each platform and the SDK packages (JS/TS, Python, Java,
  Go, .NET, Ruby, iOS, Android) into one `passbolt-<version>` artifact; a `v*` tag makes it a GitHub
  release. A change to `passbolt-ffi` or `passbolt-wasm` runs it on the pull request. To generate the
  bindings locally: `bash scripts/sdk-bindings.sh target/release/libpassbolt_ffi.so bindings [language...]`
  (Go, C# and Java need their generators, at the versions the workflow pins).

#### Submitting Changes

* Push your changes to a topic branch in your fork of the repository.
* Submit a pull request to the official passbolt repository, with the correct target branch.
