---
title: export keepass
sidebar_position: 7
---

# export keepass

Export the resources you can access to a KeePass `.kdbx` file, as the browser extension writes it.

## export keepass

Write the resources to a KeePass database, locked with a password, a key file or both.

```bash
passbolt export keepass [flags]
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `-f, --file <FILE>` | No | File to write. `-o, --output` is still accepted. Default: `passbolt-export.kdbx`. |
| `-p, --password <PASSWORD>` | No | KeePass password. Empty or left out, it is asked for (`Enter KeePass Password:`), or read from stdin when stdin is not a terminal, unless `--keyfile` is given. |
| `--keyfile <FILE>` | No | Key file locking the file, with the password or alone. Default: none. |
| `--format <FORMAT>` | No | Where the TOTP goes: `kdbx-others`, an `otpauth://` URI in a protected `otp` field (KeePassXC); `kdbx`, the `TimeOtp-*` fields of KeePass. Default: `kdbx-others`. |
| `--kdbx-version <VERSION>` | No | `v3`: KDBX 3.1 (AES-KDF, 300,000 rounds, AES-256-CBC, Salsa20); `v4`: KDBX 4 (Argon2). Default: `v3`. |
| `--folder-id <UUID>` | No | Export only this folder and its sub-folders. Default: all. |

:::note
An empty answer to the password prompt writes a file without password, as the browser extension
does. A KDBX 4 file needs a password or a key file.
:::

### Examples

#### Export the vault, typing the password at the prompt

```bash
passbolt export keepass
```

#### Export to a file with a password

```bash
passbolt export keepass -f ~/backup.kdbx -p "kdbx-master-password"
```

#### Lock the file with a key file only

```bash
passbolt export keepass -f ~/backup.kdbx --keyfile ~/backup.key
```

#### Write the TOTP as KeePass does

```bash
passbolt export keepass -f ~/backup.kdbx -p "kdbx-master-password" --format kdbx
```

#### Write a KDBX 4 file

```bash
passbolt export keepass -f ~/backup.kdbx -p "kdbx-master-password" --kdbx-version v4
```

## What the file holds

- The database and its top group are named `passbolt export`. The top group holds one sub-group
  per Passbolt folder.
- Each entry has the title, user name, password, first URI and description of the resource, its
  other URIs as `KP2A_URL`, `KP2A_URL_2`… fields, its TOTP, its expiry date, and its KeePass icon
  and background colour.
- Each custom field is a protected field named after its key. A key taken by another field
  becomes `key (1)`, `key (2)`…, with a warning on stderr.

## Resources that fail to decrypt

A resource that cannot be decrypted is reported on stdout and skipped; the export still succeeds:

```text
Skipping Export of Resource <ID> <NAME> Because of: <ERROR>
```

## Export a large vault

A large vault may need a longer `--timeout`, which bounds the whole command. See
[configuration](../configuration.md).

## Related

- [export csv](export-csv.md): the CSV file of another password manager.
- [import](import.md): import a KDBX file.
- [Backup guide](../../guides/backup.md): back up your vault.
