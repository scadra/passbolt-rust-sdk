---
title: Resources
sidebar_position: 2
---

# Resources

List, read, create, change, share, move and delete the resources (password entries) you can access.

## list resource

List the resources you can read. Aliases: `list resources`, and the verb `ls`, `index`, `filter`
or `search` in place of `list`.

```bash
passbolt list resource [flags]
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `--favorite` | No | Only the resources you marked as favorite. |
| `--own` | No | Only the resources you own. |
| `-g, --group <UUID>` | No | Only the resources shared with this group. Give one: the server filters on one group. |
| `-f, --folder <UUID>` | No | Only the resources in this folder. Repeat it for several. |
| `-s, --search <TEXT>` | No | Part of the name, in any case. v5 names are decrypted to match. |
| `-c, --column <COLUMN>` | No | Columns to show. Repeat it for several. Default: `id`, `folder_parent_id`, `name`, `username`, `uri`. Also: `password`, `description`, `created_timestamp`, `modified_timestamp`, `metadata`, `secret`, `deleted`, `expired`, `expired_at`, `resource_type_id`, and the columns added by this CLI: `uris`, `note`, `resource_type`, `personal`. |
| `--filter <EXPR>` | No | A CEL expression or a field condition. See [filters](../filters.md). |

A column name matches in any case, with or without `_`: `Username`, `username` and `URI` all work.

### Examples

#### List your own resources by name, username and URI

```bash
passbolt list resource --own -c Name -c Username -c URI
```

#### Filter on the name and print JSON

```bash
passbolt list resource --filter 'name.contains("github")' --json
```

#### List a folder, except the admin accounts

```bash
passbolt list resource --folder <FOLDER_UUID> --filter "username!=admin"
```

## get resource

Show a resource with its **decrypted** password.

```bash
passbolt get resource --id <UUID>
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `--id <UUID>` | Yes | ID of the resource. |

### Examples

#### Read a resource as JSON

```bash
passbolt get resource --id <UUID> --json
```

## get totp

Show the current TOTP code of a resource, with the seconds it remains valid.

```bash
passbolt get totp --id <UUID>
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `--id <UUID>` | Yes | ID of the resource. |

### Examples

#### Get the code to log in

```bash
passbolt get totp --id <UUID>
```

```text
123456  (17s remaining)
```

With `--json`, the command prints `{"code": …, "ttl": …}`.

## get resource permission

Show who has access to a resource. Alias: `get resource permissions`.

```bash
passbolt get resource permission --id <UUID> [flags]
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `--id <UUID>` | Yes | ID of the resource. |
| `-c, --column <COLUMN>` | No | Columns, headed as written. Repeat it for several. Default: `ID`, `Aco`, `AcoForeignKey`, `Aro`, `AroForeignKey`, `Type`. Also: `CreatedTimestamp`, `ModifiedTimestamp`. |

`Type` reads `read`, `update` or `owner`. With `--json`, every field is printed, the type as its
number.

### Examples

#### Show the access level of each user or group

```bash
passbolt get resource permission --id <UUID> -c Type -c AroForeignKey
```

## create resource

Create a resource.

```bash
passbolt create resource --name <NAME> [flags]
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `-n, --name <NAME>` | Yes, unless `--type`, `--field` or `--secret-field` is given | Name of the resource. You can also give it with `--field name=…`. |
| `-t, --type <SLUG>` | No | Resource type: `v5-default`, `v5-note`, `password-and-description`… Default: chosen from the fields given and the server's default version. |
| `-u, --username <USERNAME>` | No | Username or login. |
| `--uri <URI>` | No | URL. Repeat it for several (v5 types). |
| `-p, --password <PASSWORD>` | No | Password. When the type needs one and you leave it out, it is asked for in a terminal; a script gets `required flag "password" not set`. |
| `--generate` | No | Generate the password from the password policies of the organization. See [generate](generate.md). Cannot be used with `--password`. |
| `-d, --description <DESC>` | No | Description. |
| `--note <NOTE>` | No | Secret note, the content of a `v5-note`. |
| `--pin-code <PIN>` | No | PIN code, for `v5-pin-code`: 4 to 12 digits. |
| `--field <KEY=VALUE>` | No | Any field of the v5 metadata (or of a v4 resource). A value starting with `[` or `{` is read as JSON. Repeat it for several. |
| `--secret-field <KEY=VALUE>` | No | Any secret field, read the same way. Given alone, it also chooses the type. Repeat it for several. |
| `--totp-key <BASE32>` | No | TOTP secret, in base32. Turns on TOTP for the resource. |
| `--totp-algo <ALGO>` | No | TOTP algorithm: `SHA1`, `SHA256` or `SHA512`. Default: `SHA1`. |
| `--totp-digits <N>` | No | Number of digits of the TOTP code. Default: `6`. |
| `--totp-period <SECONDS>` | No | Period of the TOTP code, in seconds. Default: `30`. |
| `-f, --folder-parent-id <UUID>` | No | Parent folder. The resource gets the folder's permissions. |
| `--expiry <EXPIRY>` | No | Expiry date: RFC 3339, a duration such as `7d` or `48h`, or `none`. See [expiry dates](../filters.md#expiry-dates). |

### Examples

#### Create a resource in a folder, expiring in 90 days

```bash
passbolt create resource \
  --name "AWS Console" \
  --username "john@example.com" \
  --uri https://console.aws.amazon.com \
  --folder-parent-id <FOLDER_UUID> \
  --expiry "90d"
```

#### Set a KeePass icon with a JSON field

```bash
passbolt create resource --name "Router" --password <PASSWORD> \
  --field 'icon={"type":"keepass-icon-set","value":42}'
```

#### Create a resource with a generated password

```bash
passbolt create resource --name "Database" --username admin --generate
```

## update resource

Change the fields of a resource.

```bash
passbolt update resource --id <UUID> [flags]
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `--id <UUID>` | Yes | ID of the resource. |
| `-n, --name <NAME>` | No | New name. |
| `-u, --username <USERNAME>` | No | New username. |
| `--uri <URI>` | No | URL. Repeat it for several (v5 types). Replaces the current ones. |
| `-p, --password <PASSWORD>` | No | New password. |
| `--generate` | No | Generate a new password from the password policies of the organization. Cannot be used with `--password`. |
| `-d, --description <DESC>` | No | New description. |
| `--note <NOTE>` | No | Secret note (v5 types). |
| `--pin-code <PIN>` | No | PIN code, for `v5-pin-code`: 4 to 12 digits. |
| `--field <KEY=VALUE>` | No | Any field of the v5 metadata (or of a v4 resource), the value read as JSON if it is JSON. Repeat it for several. |
| `--secret-field <KEY=VALUE>` | No | Any secret field, the value read as JSON if it is JSON. Repeat it for several. |
| `--expiry <EXPIRY>` | No | Expiry date. See [expiry dates](../filters.md#expiry-dates). |
| `--totp-key <BASE32>` | No | TOTP secret, in base32. Adds or replaces the TOTP of the resource. |
| `--totp-algo <ALGO>` | No | TOTP algorithm: `SHA1`, `SHA256` or `SHA512`. |
| `--totp-digits <N>` | No | Number of digits of the TOTP code. |
| `--totp-period <SECONDS>` | No | Period of the TOTP code, in seconds. |
| `--remove-totp` | No | Remove the TOTP from the resource. |

An empty value leaves the field unchanged. Shared metadata is encrypted again for the shared
key, personal metadata for the user while only they have access.

### Examples

#### Change the password and the expiry date

```bash
passbolt update resource --id <UUID> --password "newpassword" --expiry "30d"
```

#### Replace the password with a generated one

```bash
passbolt update resource --id <UUID> --generate
```

## delete resource

Delete a resource.

```bash
passbolt delete resource --id <UUID>
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `--id <UUID>` | Yes | ID of the resource. Without it, the command fails with `no ID provided`. |

### Examples

#### Delete a resource

```bash
passbolt delete resource --id <UUID>
```

## share resource

Give users and groups access to a resource, change their access, or revoke it.

```bash
passbolt share resource --id <UUID> [flags]
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `--id <UUID>` | Yes | ID of the resource. |
| `-t, --type <TYPE>` | No | Permission: `1` (read), `7` (update), `15` (owner) or `-1` (revoke). Default: `1`. |
| `-u, --user <UUID>` | No | User to share with. Repeat it for several. |
| `-g, --group <UUID>` | No | Group to share with. Repeat it for several. |

:::note
Revoking someone who has no access fails before anything changes.
:::

### Examples

#### Give a user and a group update access

```bash
passbolt share resource --id <UUID> --type 7 --user <USER_UUID> --group <GROUP_UUID>
```

#### Revoke a user's access

```bash
passbolt share resource --id <UUID> --type -1 --user <USER_UUID>
```

## move resource

Move a resource to another folder, or to the root.

```bash
passbolt move resource --id <UUID> --folder-parent-id <FOLDER_UUID> [flags]
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `--id <UUID>` | Yes | ID of the resource. |
| `-f, --folder-parent-id <UUID>` | No | Destination folder. Empty, or left out, for the root. |
| `--with-folder-permissions` | No | Also change the permissions, as the browser extension does (owners only). Needs `--folder-parent-id`. |

With `--with-folder-permissions`, the resource loses the permissions it got from the folder it
leaves and gets the destination's, the higher level winning: no access is lowered.

### Examples

#### Move a resource into a folder

```bash
passbolt move resource --id <UUID> --folder-parent-id <FOLDER_UUID>
```

#### Move a resource to the root

```bash
passbolt move resource --id <UUID> --folder-parent-id ""
```

#### Move a resource and take the permissions of the destination

```bash
passbolt move resource --id <UUID> --folder-parent-id <FOLDER_UUID> --with-folder-permissions
```

## Related

- [Folders](folders.md): organize and share folders of resources.
- [generate](generate.md): the password policies behind `--generate`.
- [Filters](../filters.md): `--filter` expressions and expiry dates.
- [Sharing guide](../../guides/sharing.md): share with users and groups.
