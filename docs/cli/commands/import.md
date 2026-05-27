---
title: import
sidebar_position: 9
---

# import

Import a CSV file of another password manager, or a KeePass KDBX file, as the browser extension
imports it: a CSV format is recognised from its columns, everything goes into a new folder named
`import-<date>` with the folders of the file below it, and each resource is tagged with that name.

```bash
passbolt import -f vault.csv
passbolt import -f vault.csv --no-folders --no-tags --json
passbolt import -f vault.kdbx -p "<kdbx password>"
passbolt import -f vault.kdbx --keyfile vault.key
```

- Each row gets the resource type that stores what it holds (password, description, TOTP…); a
  password of 4 to 12 digits alone becomes a PIN code. The resources are personal.
- `--no-folders` puts every resource at the root, `--no-tags` leaves them untagged.
- The rows, folders or resources not imported are listed, and the command then fails.

The CSV formats are those of [export csv](export-csv.md).

## KDBX

A file ending in `.kdbx` is read as a KeePass database, KDBX 3 or 4, opened with its password
(`-p`, `--password`), its key file (`--keyfile`) or both.

- Every group becomes a folder, the root group included, and every entry a resource.
- An entry keeps its title, user name, URL and the `KP2A_URL` URLs after it (32 URLs at most),
  its notes as description, its expiry date and its TOTP (`otp` URI of KeePassXC, or the
  `TimeOtp-*` fields of KeePass).
- For v5 resources, the other fields become text custom fields, and the KeePass icon and
  background colour are kept.
