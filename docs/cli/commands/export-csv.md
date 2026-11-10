---
title: export csv
sidebar_position: 8
---

# export csv

Export your vault to the CSV file of another password manager.

## export csv

Write the resources to a CSV file as the browser extension writes it: every cell quoted, the
folder path in the folder column, the TOTP as an `otpauth://` URI.

```bash
passbolt export csv [flags]
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `--format <FORMAT>` | No | The CSV format. See [CSV formats](#csv-formats). Default: `csv-kdbx`. |
| `-f, --file <FILE>` | No | File to write. Default: `passbolt-export-<date>.csv`. |
| `--folder-id <UUID>` | No | Export only this folder and its sub-folders. Default: all. |

A resource that does not decrypt is reported on stderr (`Skipping Export of Resource <ID> <NAME>
Because of: <ERROR>`) and left out. The command then prints `Exported <N> resources to <FILE>`,
or, with `--json`, the file, the format and the number of resources.

### Examples

#### Export the whole vault for KeePass

```bash
passbolt export csv --format csv-kdbx
```

#### Export one folder for Bitwarden

```bash
passbolt export csv --format csv-bitwarden -f vault.csv --folder-id <FOLDER_UUID>
```

## CSV formats

| Format | Columns |
|---|---|
| `csv-kdbx` | KeePass: `Title`, `Username`, `URL`, `Password`, `Notes`, `Group`, `TOTP` |
| `csv-lastpass` | LastPass: `url`, `username`, `password`, `totp`, `extra`, `name`, `grouping`, `fav` |
| `csv-1password` | 1Password: `Title`, `Username`, `Url`, `Password`, `Notes`, `Type` |
| `csv-chromium` | Chromium (Chrome, Edge, Brave…): `name`, `url`, `username`, `password` |
| `csv-bitwarden` | Bitwarden: `name`, `login_username`, `login_uri`, `login_password`, `notes`, `folder`, `login_totp` |
| `csv-mozilla` | Firefox: `url`, `username`, `password`, `httpRealm`, `formActionOrigin`, `guid`, `timeCreated`, `timeLastUsed`, `timePasswordChanged` |
| `csv-safari` | Safari: `Title`, `URL`, `Username`, `Password`, `Notes`, `OTPAuth` |
| `csv-dashlane` | Dashlane: `username`, `username2`, `username3`, `title`, `password`, `note`, `url`, `category`, `otpSecret` |
| `csv-nordpass` | NordPass: `name`, `url`, `username`, `password`, `note`, `cardholername`, `cardnumber`, `cvc`, `expirydate`, `zipcode`, `folder`, `full_name`, `phone_number`, `email`, `address1`, `address2`, `city`, `country`, `state`, `type` |
| `csv-logmeonce` | LogMeOnce: `name`, `url`, `note`, `group`, `username`, `password`, `extra` |
| `csv-netwrix` | Netwrix Password Secure: `DataTags`, `Description`, `User name`, `Password`, `Internet address`, `Email address` |

## Related

- [import](import.md): import such a file.
- [export keepass](export-keepass.md): an encrypted KeePass file instead.
- [Backup guide](../../guides/backup.md): back up your vault.
