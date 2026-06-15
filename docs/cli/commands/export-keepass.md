---
title: export keepass
sidebar_position: 7
---

# export keepass

Export all accessible resources to a KeePass `.kdbx` file, as the browser extension writes it,
with the flags of go-passbolt-cli.

```bash
# Writes passbolt-export.kdbx; the KeePass password is prompted (or read from stdin when piped):
passbolt export keepass
passbolt export keepass -f ~/backup.kdbx -p "kdbx-master-password"
passbolt export keepass -f ~/backup.kdbx --keyfile ~/backup.key
passbolt export keepass -f ~/backup.kdbx -p "kdbx-master-password" --format kdbx
passbolt export keepass -f ~/backup.kdbx -p "kdbx-master-password" --kdbx-version v4
```

| Flag | Default | |
|---|---|---|
| `-f, --file` | `passbolt-export.kdbx` | Output file (`-o, --output` still accepted) |
| `-p, --password` | prompt | KeePass password; empty or missing prompts `Enter KeePass Password:`, unless `--keyfile` is given |
| `--keyfile` | none | Key file locking the file, with the password or alone |
| `--format` | `kdbx-others` | Where the TOTP goes: `kdbx-others`, an `otpauth://` URI in a protected `otp` field (KeePassXC); `kdbx`, the `TimeOtp-*` fields of KeePass |
| `--kdbx-version` | `v3` | `v3`: KDBX 3.1 (AES-KDF, 300,000 rounds, AES-256-CBC, Salsa20); `v4`: KDBX 4 (Argon2) |
| `--folder-id` | all | Export one folder and its sub-folders |

The database and its top group are named `passbolt export`; the top group holds one sub-group
per Passbolt folder. Each entry has the title, user name, password, first URI and description of
the resource, its other URIs as `KP2A_URL`, `KP2A_URL_2`… fields, its TOTP, its expiry date and
its KeePass icon and background colour. Each custom field is a protected field named after its
key; a key taken by another field becomes `key (1)`, `key (2)`…, with a warning on stderr.

An empty answer to the password prompt writes a file without password, as the browser extension
does; a KDBX 4 file needs a password or a key file.

A resource that cannot be decrypted is reported on stdout (`Skipping Export of Resource <id>
<name> Because of: <error>`) and skipped; the export still succeeds, as with go-passbolt-cli.

A large vault may need a longer `--timeout`, which bounds the whole command.
