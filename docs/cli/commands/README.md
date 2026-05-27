---
title: Commands
sidebar_position: 1
---

# Commands

| Page | Commands |
|---|---|
| [Resources](resources.md) | `list`, `get`, `get totp`, `get … permission`, `create`, `update`, `delete`, `share`, `move` |
| [Folders](folders.md) | `list`, `get`, `get … permission`, `create`, `update`, `delete`, `share`, `move` |
| [Users](users.md) | `list`, `get`, `create`, `update`, `delete` |
| [Groups](groups.md) | `list`, `get`, `create`, `update`, `delete` |
| [exec](exec.md) | run a command with secrets in its environment |
| [export keepass](export-keepass.md) | a KeePass `.kdbx` file of the vault |
| [export csv](export-csv.md) | the CSV file of another password manager |
| [import](import.md) | a CSV file of another password manager, or a KeePass KDBX file |
| [migrate-metadata](migrate-metadata.md) | upgrade v4 resources to v5 |

`configure` and `verify` are described in [configuration](../configuration.md) and
[authentication](../authentication.md), `completion` in [installation](../../getting-started/installation.md#shell-completion).

The options of each command are also in `passbolt <verb> <entity> --help`, and `passbolt gendoc
--type markdown|man` writes them all to `./doc` or `./man`.
