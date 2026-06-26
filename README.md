
	      ____                  __          ____
	     / __ \____  _____ ____/ /_  ____  / / /_
	    / /_/ / __ `/ ___/ ___/ __ \/ __ \/ / __/
	   / ____/ /_/ (__  |__  ) /_/ / /_/ / / /_
	  /_/    \__,_/____/____/_.___/\____/_/\__/

	Open source password manager for teams
	(c) 2025 Passbolt SA
	https://www.passbolt.com

## License

Passbolt - Open source password manager for teams

(c) 2025 Passbolt SA

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General
Public License (AGPL) as published by the Free Software Foundation version 3.

The name "Passbolt" is a registered trademark of Passbolt SA, and Passbolt SA hereby declines to grant a trademark
license to "Passbolt" pursuant to the GNU Affero General Public License version 3 Section 7(e), without a separate
agreement with Passbolt SA.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along with this program. If not,
see [GNU Affero General Public License v3](http://www.gnu.org/licenses/agpl-3.0.html).

## About passbolt

Passbolt is an open source password manager for teams. It allows to securely share and store credentials.
For instance, the wifi password of your office, or the administrator password of a router, or your organisation social
media account password, all of them can be secured using Passbolt.

You can try a demo of passbolt at [https://demo.passbolt.com](https://demo.passbolt.com).

## About passbolt-rs

A fast, secure CLI and SDK for [Passbolt](https://www.passbolt.com/) — written in Rust.

Full alternative to [go-passbolt-cli](https://github.com/passbolt/go-passbolt-cli) with no OpenSSL dependency (pure Rust TLS + GPG).
The workspace also ships the `passbolt-sdk` library and its WASM and FFI bindings.

# Contributing

Please check [CONTRIBUTING.md](CONTRIBUTING.md) for more information about how to get involved.

## Reporting a security Issue

If you've found a security related issue in Passbolt, please don't open an issue on GitHub. Follow our responsible disclosure process: https://www.passbolt.com/docs/contribute/security/vulnerability/.

# Quick how-to

```bash
# Install (Rust 1.88+, no OpenSSL), or take the binary of a release
cargo install --path crates/passbolt-cli

# Save your settings, then pin the server's identity
passbolt configure \
  --server-address https://passbolt.example.com \
  --user-private-key-file ~/passbolt-private.asc \
  --user-password "my-passphrase"
passbolt verify

# Read and write
passbolt list resource
passbolt get resource --id <UUID>
passbolt create resource --name "GitHub" --username "john" --uri https://github.com
```

`passbolt` accepts go-passbolt-cli's commands, flags, variables, config file and filters, and
prints the same output: see [Coming from go-passbolt-cli](docs/cli/go-passbolt-cli.md).

## Documentation

The documentation is in [`docs/`](docs/README.md), also published as a site on
[GitHub Pages](https://scadra.github.io/passbolt-rust-sdk/):

- [Installation](docs/getting-started/installation.md) and [quick start](docs/getting-started/quick-start.md)
- [CLI](docs/cli/README.md): [configuration](docs/cli/configuration.md),
  [authentication and MFA](docs/cli/authentication.md), [commands](docs/cli/commands/README.md),
  [output](docs/cli/output.md), [filters](docs/cli/filters.md)
- [SDK](docs/sdk/README.md): [Rust](docs/sdk/rust.md), [JavaScript/TypeScript](docs/sdk/javascript.md),
  [Python](docs/sdk/python.md), [Java](docs/sdk/java.md), [Android](docs/sdk/android.md),
  [.NET](docs/sdk/dotnet.md), [Go](docs/sdk/go.md), [Ruby](docs/sdk/ruby.md), [Swift](docs/sdk/swift.md)
- [Security](docs/security.md)
- [Development](docs/contributing/development.md), [bindings and CI](docs/contributing/bindings-and-ci.md),
  [publishing](docs/contributing/publishing.md)

# Credits

https://www.passbolt.com/credits
