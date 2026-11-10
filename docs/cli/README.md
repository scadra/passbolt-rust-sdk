---
title: Overview
sidebar_position: 1
---

# The `passbolt` CLI

Read, write, share and use the secrets of your Passbolt server from a terminal or a script.

## Command structure

Each command is a verb, then the kind of item it acts on:

```text
passbolt [GLOBAL FLAGS] <verb> <entity> [OPTIONS]
```

| Verb | Entities |
|---|---|
| `list` | `resource`, `folder`, `user`, `group` |
| `get` | `resource`, `totp`, `folder`, `user`, `group`, `resource permission`, `folder permission` |
| `create` | `resource`, `folder`, `user`, `group` |
| `update` | `resource`, `folder`, `user`, `group` |
| `delete` | `resource`, `folder`, `user`, `group` |
| `share` | `resource`, `folder` |
| `move` | `resource`, `folder` |

The other commands take no entity: `tui`, `generate`, `configure`, `verify`, `exec`,
`export keepass`, `export csv`, `import`, `migrate-metadata`, `completion` and `gendoc`.

Run `passbolt <command> --help` to see what a command does and its flags. Each verb also has
aliases, such as `ls` for `list`: see [commands](commands/README.md#verb-aliases).

## Errors and output streams

An error prints `Error: <message>` on stderr and exits with code `1`, usage errors included.

Prompts and warnings also go to stderr, so the `--json` output on stdout stays clean for `jq`.

## Related

- [Configuration](configuration.md): config file, global flags, environment variables.
- [Authentication](authentication.md): GPGAuth, pinning the server key, MFA.
- [TLS and proxies](tls.md): certificates, mutual TLS, proxies.
- [Commands](commands/README.md): every command and its options.
- [Output](output.md): tables, JSON, key-value.
- [Filters](filters.md): `--filter` expressions and expiry dates.
- [Terminal UI](tui.md): `passbolt tui`, browse and copy from the keyboard.
- [Troubleshooting](troubleshooting.md): error messages, their causes and fixes, exit codes.
