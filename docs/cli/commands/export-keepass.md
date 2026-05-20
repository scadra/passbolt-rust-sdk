---
title: export keepass
sidebar_position: 7
---

# export keepass

Export all accessible resources to a KeePass `.kdbx` file, with the flags of go-passbolt-cli.

```bash
# Writes passbolt-export.kdbx; the KeePass password is prompted (or read from stdin when piped):
passbolt export keepass
passbolt export keepass -f ~/backup.kdbx -p "kdbx-master-password"
passbolt export keepass -f ~/backup.kdbx -p "kdbx-master-password" --kdbx-version v4
```

| Flag | Default | |
|---|---|---|
| `-f, --file` | `passbolt-export.kdbx` | Output file (`-o, --output` still accepted) |
| `-p, --password` | prompt | KeePass password; empty or missing prompts `Enter KeePass Password:` |
| `--kdbx-version` | `v3` | `v3`: KDBX 3.1 (AES-KDF, AES-256-CBC, Salsa20); `v4`: KDBX 4 (Argon2) |
| `--folder-id` | all | Export one folder and its sub-folders |

The database is named `Passbolt Export`; its `root` group holds one sub-group per Passbolt
folder. Each entry has the title, username, URL, password and notes of the resource, its TOTP as
an `otpauth://` URI in a protected `otp` field (issuer: the URI, else the name), and each custom
field as a protected field named after it.

A resource that cannot be decrypted is reported on stdout (`Skipping Export of Resource <id>
<name> Because of: <error>`) and skipped; the export still succeeds, as with go-passbolt-cli.

Unlike go-passbolt-cli, an empty password is refused instead of writing a file without
credentials, and v3 files use 60,000 AES-KDF rounds (KeePass 2.x default) instead of 6,000.

A large vault may need a longer `--timeout`, which bounds the whole command.
