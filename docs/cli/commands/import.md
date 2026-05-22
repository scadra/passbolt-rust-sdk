---
title: import
sidebar_position: 9
---

# import

Import a CSV file of another password manager, as the browser extension imports it: its format
is recognised from its columns, everything goes into a new folder named `import-<date>` with the
folders of the file below it, and each resource is tagged with that name.

```bash
passbolt import -f vault.csv
passbolt import -f vault.csv --no-folders --no-tags --json
```

- Each row gets the resource type that stores what it holds (password, description, TOTP…); a
  password of 4 to 12 digits alone becomes a PIN code. The resources are personal.
- `--no-folders` puts every resource at the root, `--no-tags` leaves them untagged.
- The rows, folders or resources not imported are listed, and the command then fails.

The formats are those of [export csv](export-csv.md).
