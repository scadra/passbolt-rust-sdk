---
title: Quick start
sidebar_position: 2
---

# Quick start

Connect the CLI to your Passbolt server, then read, write and use your secrets.

## Prerequisites

- The `passbolt` CLI. See [installation](installation.md).
- The address of your Passbolt server.
- The OpenPGP private key of your Passbolt account, exported from the browser extension, and its
  passphrase.

## 1. Save your settings

```bash
passbolt configure \
  --server-address https://passbolt.example.com \
  --user-private-key-file ~/passbolt-private.asc \
  --user-password "my-passphrase"
```

The CLI copies the key into `~/.config/passbolt/config.toml`, which only you can read.

:::tip
Leave `--user-password` out and the CLI asks for the passphrase at each command.
:::

## 2. Pin the server's identity

```bash
passbolt verify
```

The server proves it holds its private key, and the CLI saves that key. Each later login checks
it again, so another server answering at the same address is refused.

## 3. Read your secrets

```bash
passbolt list resource
passbolt list resource --search github
passbolt get resource --id <UUID>
```

`list resource` shows the ID, folder, name, username and URI of each resource; `get resource`
decrypts the password and the description. Add `--json` to read the output with `jq`:

```bash
passbolt list resource --json | jq '.[].name'
```

## 4. Create and share a resource

```bash
passbolt create resource --name "GitHub" --username "john" --uri https://github.com
passbolt share resource --id <UUID> --type 7 --user <USER_UUID>
```

`create resource` asks for the password when you leave `--password` out.

## 5. Use a secret without printing it

```bash
export PGPASSWORD="passbolt://<UUID>"
passbolt exec -- psql -U myuser -d mydb
```

`exec` replaces each variable holding a `passbolt://` URI with the password of that resource,
for the command it runs only. `psql` reads its password from `PGPASSWORD`.

## Next steps

- [Commands](../cli/commands/README.md): every command and its flags.
- [Output](../cli/output.md) and [filters](../cli/filters.md): tables, JSON and `--filter`.
- [Authentication](../cli/authentication.md#mfa): accounts with MFA.
- [Configuration](../cli/configuration.md): every setting.
