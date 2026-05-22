---
title: Introduction
sidebar_position: 1
slug: /
---

# passbolt-rust

A command-line client and an SDK for [Passbolt](https://www.passbolt.com), the open source
password manager for teams, written in Rust: pure Rust TLS ([rustls](https://github.com/rustls/rustls))
and OpenPGP ([rPGP](https://github.com/rpgp/rpgp)), no OpenSSL.

## What is in it

| Part | What for | Where |
|---|---|---|
| `passbolt` CLI | Scripts, CI jobs, terminals: list, read, create, share and export secrets. A drop-in replacement for [go-passbolt-cli](https://github.com/passbolt/go-passbolt-cli). | [CLI](cli/README.md) |
| `passbolt-sdk` | The Rust library the CLI is built on: login, resources, folders, users, groups, sharing, metadata v5. | [Rust](sdk/rust.md) |
| SDK bindings | The same library from JavaScript/TypeScript, Python, Java, Android, .NET, Go, Ruby and Swift. | [SDK](sdk/README.md) |

All of them log in as the browser extension does (GPGAuth), encrypt and decrypt on the client,
and understand both v4 resources and v5 encrypted metadata.

## Where to start

- **Use Passbolt from a terminal or a script**: [install the CLI](getting-started/installation.md),
  then follow the [quick start](getting-started/quick-start.md).
- **Coming from go-passbolt-cli**: your commands, variables and config file keep working; see
  [what differs](cli/go-passbolt-cli.md).
- **Call Passbolt from an application**: read the [SDK overview](sdk/README.md), then the page of
  your language.
- **Work on passbolt-rust itself**: [development](contributing/development.md).

## License

AGPL-3.0-or-later. The name "Passbolt" is a registered trademark of Passbolt SA.
