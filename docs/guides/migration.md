---
title: Migration
sidebar_position: 7
---

# Migration from another password manager

`passbolt import` reads the export of another password manager, as the browser extension imports
it, and creates the resources in Passbolt. See [import](../cli/commands/import.md).

## 1. Export from the other password manager

`import` reads:

| Source | File |
|---|---|
| KeePass, KeePassXC | a KDBX file (`.kdbx`, KDBX 3 or 4), or its CSV export |
| LastPass | CSV |
| 1Password | CSV |
| Bitwarden | CSV |
| Chrome, Edge, Brave and other Chromium browsers | CSV |
| Firefox | CSV |
| Safari | CSV |
| Dashlane | CSV |
| NordPass | CSV |
| LogMeOnce | CSV |
| Netwrix Password Secure | CSV |

A file ending in `.kdbx` is read as a KeePass database; any other file as CSV, its format
recognised from its column names. The columns of each format are listed in
[export csv](../cli/commands/export-csv.md). A CSV file must be UTF-8.

A KDBX file keeps more than a CSV: groups, several URLs, expiry dates, TOTP, custom fields,
icons. Prefer it when the source can write one.

The export file holds every password in clear (CSV) or behind one password (KDBX). Write it on an
encrypted disk, and destroy it at the end (`shred -u`).

## 2. Import

```bash
passbolt import -f lastpass_export.csv --json > import.json
passbolt import -f vault.kdbx -p "$KDBX_PASSWORD" --json > import.json
passbolt import -f vault.kdbx --keyfile vault.key --json > import.json
```

- Everything goes into a new folder named `import-<date>` (for example `import-20261110093000`),
  with the folders of the file below it. `--no-folders` leaves out the folders of the file.
- Each resource is tagged with the same name. `--no-tags` leaves them untagged.
- Each row gets the resource type that stores what it holds: password, description, TOTP… A
  password of 4 to 12 digits alone becomes a PIN code.
- The resources and folders are personal: only the account that imports them can see them.

The report, with `--json`:

```json
{
  "reference": "import-20261110093000",
  "resources": 412,
  "folders": 23,
  "folder_id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
  "tag": "import-20261110093000",
  "errors": [],
  "warnings": []
}
```

Each entry of `errors` and `warnings` has a `title`, a `detail` and the `item` it is about (the
name of the resource, or the path of the folder). When an item was not imported, the command
lists it and exits with code 1, after importing the others: do not run it again on the same file,
or the rest is imported twice. Fix the rows concerned and import them alone, or delete the import
and start again:

```bash
passbolt delete folder --id "$(jq -r .folder_id import.json)" --cascade
```

Large files may need a longer `--timeout` (default `1m`, for the whole command).

## 3. Put the import in its place

The import folder can be moved below an existing folder:

```bash
import_folder=$(jq -r .folder_id import.json)

passbolt move folder --id "$import_folder" --folder-parent-id "$TEAM_FOLDER_ID" \
  --with-folder-permissions
passbolt update folder --id "$import_folder" --name "From LastPass"
```

`--with-folder-permissions` gives the folder the permissions of the destination, and copies the
change onto the sub-folders and resources the user owns, as the browser extension does. Only an
owner of the folder can. Without it, the folder and its content keep their permissions: personal,
here.

A single resource is moved the same way:

```bash
passbolt move resource --id <UUID> --folder-parent-id "$TEAM_FOLDER_ID" --with-folder-permissions
```

## 4. Check the result

The folders imported, and the resources at the top of the import folder:

```bash
passbolt list folder --folder "$import_folder" -c id -c name
passbolt list resource --folder "$import_folder" -c name -c username -c uri
```

`list resource --folder` lists one level; repeat `--folder` for the sub-folders. Count all the
resources of the import from the list of folders:

```bash
folders=$(passbolt list folder -c id -c folder_parent_id --json \
  | jq -r --arg root "$import_folder" '
      . as $all
      | def below($id): $id, ($all[] | select(.folder_parent_id == $id) | .id | below(.));
      below($root)')

args=()
for folder in $folders; do args+=(--folder "$folder"); done
passbolt list resource "${args[@]}" -c id --json | jq length
```

Compare the count with the number of entries of the source and with `resources` in the report.
Then open a few resources, those with TOTP and custom fields first:

```bash
passbolt get resource --id <UUID>
passbolt get totp --id <UUID>
```

## 5. Share with the teams

Share each folder with the group that uses it. `--with-content` copies the new permission onto
the sub-folders and resources inside:

```bash
group_id=$(passbolt list group --filter 'name == "DevOps"' -c id --json | jq -r '.[0].id')

passbolt share folder --id "$import_folder" --type 7 --group "$group_id" --with-content
```

`7` lets the group read and edit, `1` only read, `15` makes it owner. See [sharing](sharing.md)
for the permissions, groups and folders.

## 6. Clean up

- Destroy the export file of the old password manager, and its copies.
- Change the master password of the old password manager, or close the account, once the teams
  use Passbolt.
- The passwords themselves did not change: rotate the most sensitive ones (see
  [rotating a password](rotation.md)).
