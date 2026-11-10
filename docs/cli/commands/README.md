---
title: Commands
sidebar_position: 1
---

# Commands

Find the command you need, then its flags and examples on its page.

## Commands by page

| Page | Commands |
|---|---|
| [Resources](resources.md) | `list`, `get`, `get totp`, `get … permission`, `create`, `update`, `delete`, `share`, `move` |
| [Folders](folders.md) | `list`, `get`, `get … permission`, `create`, `update`, `delete`, `share`, `move` |
| [Users](users.md) | `list`, `get`, `create`, `update`, `delete` |
| [Groups](groups.md) | `list`, `get`, `create`, `update`, `delete` |
| [exec](exec.md) | Run a command with secrets in its environment. |
| [export keepass](export-keepass.md) | Write a KeePass `.kdbx` file of the vault. |
| [export csv](export-csv.md) | Write the CSV file of another password manager. |
| [import](import.md) | Import a CSV file of another password manager, or a KeePass KDBX file. |
| [migrate-metadata](migrate-metadata.md) | Upgrade v4 resources to v5. |
| [generate](generate.md) | Generate a password, passphrase or PIN code from the password policies. |
| [tui](../tui.md) | Browse, copy and edit the resources from the keyboard. |

`configure` and `verify` are described in [configuration](../configuration.md) and
[authentication](../authentication.md), `completion` in
[installation](../../getting-started/installation.md#shell-completion).

## Verb aliases

Each verb also has other names:

| Verb | Aliases |
|---|---|
| `create` | `new` |
| `get` | `read` |
| `list` | `index`, `ls`, `filter`, `search` |
| `update` | `change` |
| `delete` | `remove` |

## Global flags

The flags for the server address, private key, passphrase, MFA, TLS, proxy, timeout, workers,
debug output and `--json` work with every command. They are listed once, in
[configuration](../configuration.md), and not repeated on each command page.

## Get help in the terminal

Run `passbolt <verb> <entity> --help` to see the flags of a command.

To write the reference of every command to files, one file per command, run `gendoc`:

```bash
passbolt gendoc [flags]
```

| Flag | Required | Description |
|---|---|---|
| `-t, --type <TYPE>` | No | `markdown` or `man`. Default: `markdown`. |
| `-o, --output-dir <DIR>` | No | Folder to write into, created if absent. Default: `./doc` for `markdown`, `./man` for `man`. |

```bash
passbolt gendoc --type man -o ./share/man
```

## Related

- [Configuration](../configuration.md): global flags and the config file.
- [Output](../output.md): tables, JSON and key-value output.
- [Filters](../filters.md): `--filter` expressions and expiry dates.
