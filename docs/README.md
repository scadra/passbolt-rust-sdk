---
title: Introduction
sidebar_position: 1
slug: /
---

# passbolt-rust

Use [Passbolt](https://www.passbolt.com), the open source password manager for teams, from a
terminal, a script or your own application.

passbolt-rust is a command-line client and an SDK written in Rust. It uses pure Rust TLS
([rustls](https://github.com/rustls/rustls)), with no OpenSSL, and the OpenPGP libraries of Proton:
[GopenPGP](https://github.com/ProtonMail/gopenpgp) natively and
[OpenPGP.js](https://github.com/openpgpjs/openpgpjs) in JavaScript. See
[OpenPGP engines](security.md#openpgp-engines).

## What is included

| Part | What for | Where |
|---|---|---|
| `passbolt` CLI | Scripts, CI jobs, terminals: list, read, create, share and export secrets. | [CLI](cli/README.md) |
| `passbolt-sdk` | The Rust library the CLI is built on: login, resources, folders, users, groups, sharing, metadata v5. | [Rust](sdk/rust.md) |
| SDK bindings | The same library from JavaScript/TypeScript, Python, Java, Android, .NET, Go, Ruby and Swift. | [SDK](sdk/README.md) |

All of them:

- log in as the browser extension does (GPGAuth);
- encrypt and decrypt on the client;
- work with both v4 resources and v5 encrypted metadata.

## License

AGPL-3.0-or-later. The name "Passbolt" is a registered trademark of Passbolt SA.

## Next steps

- **Use Passbolt from a terminal or a script**: [install the CLI](getting-started/installation.md),
  then follow the [quick start](getting-started/quick-start.md). The [guides](guides/README.md)
  show it in CI, scripts, backups and migrations.
- **Understand what the client does**: read [concepts](concepts.md) (keys, v4 and v5 resources,
  metadata keys, permissions) and [security](security.md).
- **Call Passbolt from an application**: read the [SDK overview](sdk/README.md), then the page of
  your language and the [API reference](sdk/api.md). [Upgrading](sdk/upgrading.md) lists the
  changes since 0.1.1.
- **Fix something that fails**: see [troubleshooting](cli/troubleshooting.md).
- **Work on passbolt-rust itself**: read [development](contributing/development.md) and
  [architecture](contributing/architecture.md).
