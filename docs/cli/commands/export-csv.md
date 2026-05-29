---
title: export csv
sidebar_position: 8
---

# export csv

Export to the CSV file of another password manager, as the browser extension writes it: every
cell quoted, the folder path in the folder column, the TOTP as an `otpauth://` URI.

```bash
passbolt export csv --format csv-kdbx                      # passbolt-export-<date>.csv
passbolt export csv --format csv-kdbx -f vault.csv --folder-id <FOLDER_UUID>
```

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

A resource that does not decrypt is reported and left out.

To import such a file, see [import](import.md).
