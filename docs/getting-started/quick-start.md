---
title: Quick start
sidebar_position: 2
---

# Quick start

You need the address of your Passbolt server, your OpenPGP private key (the one of your Passbolt
account, exported from the browser extension) and its passphrase.

## 1. Save your settings

```bash
passbolt configure \
  --server-address https://passbolt.example.com \
  --user-private-key-file ~/passbolt-private.asc \
  --user-password "my-passphrase"
```

The content of the key file is saved in `~/.config/passbolt/config.toml`, readable by you only.
Leave `--user-password` out to be asked for it at each command instead. See
[configuration](../cli/configuration.md) for every setting.

## 2. Pin the server's identity

```bash
passbolt verify
```

The server proves it holds its private key, and its key is saved: each later login checks it
again, so another server answering at the same address is refused. Recommended, see
[authentication](../cli/authentication.md).

## 3. Read your secrets

```bash
passbolt list resource                       # id, folder, name, username, uri
passbolt list resource --search github       # names holding "github", any case
passbolt get resource --id <UUID>            # decrypted password, description, …
passbolt list resource --json | jq '.[].name'
```

## 4. Write

```bash
passbolt create resource --name "GitHub" --username "john" --uri https://github.com
passbolt share resource --id <UUID> --type 7 --user <USER_UUID>
```

`create resource` asks for the password when it is not given.

## 5. Use a secret without printing it

```bash
export DB_PASSWORD="passbolt://<UUID>"
passbolt exec -- psql -U myuser -d mydb
```

## Next

- Every command: [commands](../cli/commands/README.md).
- Tables, JSON and `--filter`: [output](../cli/output.md), [filters](../cli/filters.md).
- MFA accounts: [authentication](../cli/authentication.md#mfa).
