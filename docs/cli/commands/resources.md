---
title: Resources
sidebar_position: 2
---

# Resources

## list resource

```bash
passbolt list resource [OPTIONS]
```

| Option | Description |
|---|---|
| `--favorite` | Only show favorited entries |
| `--own` | Only show entries owned by the current user |
| `-g, --group <UUID>` | Only the resources shared with this group (one) |
| `-f, --folder <UUID>` | Filter by folder (repeatable) |
| `-s, --search <TEXT>` | Part of the name, any case (v5 names decrypted) |
| `-c, --column <COL>` | Columns (repeatable), default `id`, `folder_parent_id`, `name`, `username`, `uri`; also `password`, `description`, `created_timestamp`, `modified_timestamp`, `metadata`, `secret`, `deleted`, `expired`, `expired_at`, `resource_type_id`, and ours: `uris`, `note`, `resource_type`, `personal` |
| `--filter <EXPR>` | CEL expression or field condition (see [filters](../filters.md)) |

The command is also `passbolt ls resources`, `index`, `filter` or `search`.

```bash
passbolt list resource
passbolt list resource --own -c Name -c Username -c URI
passbolt list resource --filter 'name.contains("github")' --json
passbolt list resource --folder <FOLDER_UUID> --filter "username!=admin"
```

## get resource

A resource with its **decrypted** password.

```bash
passbolt get resource --id <UUID>
passbolt get resource --id <UUID> --json
```

## get totp

The current TOTP code of a resource, with the seconds it remains valid.

```bash
passbolt get totp --id <UUID>
```

## get resource permission

Who has access to a resource (also `get resource permissions`). Columns, headed as written:
`ID`, `Aco`, `AcoForeignKey`, `Aro`, `AroForeignKey`, `Type` (the default), plus
`CreatedTimestamp`, `ModifiedTimestamp`. `Type` reads `read`, `update` or `owner`. With `--json`,
every field is printed, the type as its number.

```bash
passbolt get resource permission --id <UUID>
passbolt get resource permission --id <UUID> -c Type -c AroForeignKey
```

## create resource

```bash
passbolt create resource --name <NAME> [OPTIONS]
```

| Option | Description |
|---|---|
| `-n, --name <NAME>` | Entry name; required unless `--type`, `--field` or `--secret-field` is given (`--field name=…`) |
| `-t, --type <SLUG>` | Resource type (`v5-default`, `v5-note`, `password-and-description`…); by default from the fields given and the server's default version |
| `-u, --username <USERNAME>` | Username |
| `--uri <URI>` | URL (repeatable for v5 types) |
| `-p, --password <PASSWORD>` | Password (prompted securely when the type needs one) |
| `-d, --description <DESC>` | Description |
| `--note <NOTE>` | Secret note (`v5-note`) |
| `--pin-code <PIN>` | PIN code (`v5-pin-code`, 4 to 12 digits) |
| `--field <KEY=VALUE>` | Any metadata field, the value read as JSON if it is JSON (repeatable) |
| `--secret-field <KEY=VALUE>` | Any secret field, idem; alone, it also chooses the type |
| `--totp-key <BASE32>` | TOTP secret, with `--totp-algo`, `--totp-digits`, `--totp-period` |
| `-f, --folder-parent-id <UUID>` | Parent folder: the resource gets its permissions |
| `--expiry <EXPIRY>` | Expiry date (see [expiry dates](../filters.md#expiry-dates)) |

```bash
passbolt create resource \
  --name "AWS Console" \
  --username "john@example.com" \
  --uri https://console.aws.amazon.com \
  --folder-parent-id <FOLDER_UUID> \
  --expiry "90d"
```

## update resource

```bash
passbolt update resource --id <UUID> [OPTIONS]
```

Options: `--name`, `--username`, `--uri`, `--password`, `--description`, `--note`, `--pin-code`,
`--field`, `--secret-field`, `--expiry`, `--totp-*`, `--remove-totp`. An empty value leaves the
field unchanged. Shared metadata is encrypted again for the shared key, personal metadata for the
user while only they have access.

```bash
passbolt update resource --id <UUID> --password "newpassword" --expiry "30d"
```

## delete resource

```bash
passbolt delete resource --id <UUID>
```

## share resource

```bash
passbolt share resource --id <UUID> [OPTIONS]
```

| Option | Description |
|---|---|
| `-t, --type <TYPE>` | Permission: `1`=Read, `7`=Update, `15`=Owner, `-1`=Revoke (default: `1`) |
| `-u, --user <UUID>` | User to share with (repeatable) |
| `-g, --group <UUID>` | Group to share with (repeatable) |

Revoking someone without access fails before anything changes.

```bash
passbolt share resource --id <UUID> --type 7 --user <USER_UUID> --group <GROUP_UUID>
```

## move resource

```bash
passbolt move resource --id <UUID> --folder-parent-id <FOLDER_UUID>
# Move to root:
passbolt move resource --id <UUID> --folder-parent-id ""
# Also change the permissions, as the browser extension does (owners only):
passbolt move resource --id <UUID> --folder-parent-id <FOLDER_UUID> --with-folder-permissions
```

With `--with-folder-permissions`, the resource loses the permissions it got from the folder it
leaves and gets the destination's, the higher level winning: no access is lowered.
