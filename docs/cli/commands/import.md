---
title: import
sidebar_position: 9
---

# import

Import a CSV file of another password manager, or a KeePass KDBX file, as the browser extension
imports it.

## import

Import the resources of a file into a new folder named `import-<date>`, with the folders of the
file below it. Each resource is tagged with that name.

```bash
passbolt import --file <FILE> [flags]
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `-f, --file <FILE>` | Yes | The CSV or KDBX file to import. A CSV format is recognised from its columns; a file ending in `.kdbx` is read as a KeePass database. |
| `-p, --password <PASSWORD>` | No | Password of the KDBX file. |
| `--keyfile <FILE>` | No | Key file of the KDBX file. |
| `--no-folders` | No | Put every resource at the root of the import folder, without the folders of the file. |
| `--no-tags` | No | Do not tag the imported resources with the name of the import. |

- Each row gets the resource type that stores what it holds (password, description, TOTP…). A
  password of 4 to 12 digits alone becomes a PIN code. The resources are personal.
- The rows, folders or resources not imported are listed, and the command then fails with
  `<N> items were not imported`.

The CSV formats are those of [export csv](export-csv.md#csv-formats).

### Examples

#### Import a CSV file

```bash
passbolt import -f vault.csv
```

```text
Imported <N> resources and <N> folders in import-<date>
```

#### Import without folders or tags, and print JSON

```bash
passbolt import -f vault.csv --no-folders --no-tags --json
```

#### Import a KeePass file with its password

```bash
passbolt import -f vault.kdbx -p "<KDBX_PASSWORD>"
```

#### Import a KeePass file with its key file

```bash
passbolt import -f vault.kdbx --keyfile vault.key
```

## KDBX

A file ending in `.kdbx` is read as a KeePass database, KDBX 3 or 4, opened with its password
(`-p`, `--password`), its key file (`--keyfile`) or both.

- Every group becomes a folder, the root group included, and every entry a resource.
- An entry keeps its title, user name, URL and the `KP2A_URL` URLs after it (32 URLs at most),
  its notes as description, its expiry date and its TOTP (`otp` URI of KeePassXC, or the
  `TimeOtp-*` fields of KeePass).
- For v5 resources, the other fields become text custom fields, and the KeePass icon and
  background colour are kept.

## Related

- [export csv](export-csv.md): the CSV formats.
- [export keepass](export-keepass.md): write a KDBX file.
- [Migration guide](../../guides/migration.md): move from another password manager.
