---
title: Overview
sidebar_position: 1
---

# The `passbolt` CLI

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

And `configure`, `verify`, `exec`, `export keepass`, `export csv`, `import`, `migrate-metadata`,
`completion`, `gendoc`.
`passbolt <command> --help` describes each one.

## Pages

- [Configuration](configuration.md): config file, global flags, environment variables.
- [Authentication](authentication.md): GPGAuth, pinning the server key, MFA.
- [TLS and proxies](tls.md): certificates, mutual TLS, proxies.
- [Commands](commands/README.md): every command and its options.
- [Output](output.md): tables, JSON, key-value.
- [Filters](filters.md): `--filter` expressions and expiry dates.
- [Coming from go-passbolt-cli](go-passbolt-cli.md).

## Errors

Errors print `Error: <message>` on stderr and exit with code 1, usage errors included. Prompts
and warnings go to stderr too, so that `--json` output stays clean.
