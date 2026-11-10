---
title: Folders
sidebar_position: 3
---

# Folders

List, read, create, rename, share, move and delete the folders you can access.

## list folder

List the folders. Alias: `list folders`.

```bash
passbolt list folder [flags]
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `-s, --search <TEXT>` | No | Search by name. |
| `-f, --folder <UUID>` | No | Only the folders in this parent folder. Repeat it for several. |
| `-g, --group <UUID>` | No | Only the folders shared with one of these groups. Repeat it for several. |
| `-c, --column <COLUMN>` | No | Columns to show. Repeat it for several. Default: `id`, `folder_parent_id`, `name`. Also: `created_timestamp`, `modified_timestamp`, `personal`. |
| `--filter <EXPR>` | No | A CEL expression or a field condition. See [filters](../filters.md). |

### Examples

#### List the sub-folders of a folder

```bash
passbolt list folder --folder <PARENT_UUID>
```

#### List the folders shared with a group

```bash
passbolt list folder --group <GROUP_UUID> -c name
```

## get folder

Show the parent folder and the name of a folder.

```bash
passbolt get folder --id <UUID>
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `--id <UUID>` | Yes | ID of the folder. |

### Examples

#### Read a folder as JSON

```bash
passbolt get folder --id <UUID> --json
```

## get folder permission

Show who has access to a folder. Alias: `get folder permissions`.

```bash
passbolt get folder permission --id <UUID> [flags]
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `--id <UUID>` | Yes | ID of the folder. |
| `-c, --column <COLUMN>` | No | The same columns as [get resource permission](resources.md#get-resource-permission). Repeat it for several. |

### Examples

#### Show who has access to a folder

```bash
passbolt get folder permission --id <UUID>
```

## create folder

Create a folder, at the root or in another folder.

```bash
passbolt create folder --name <NAME> [flags]
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `-n, --name <NAME>` | Yes | Name of the folder. |
| `-f, --folder-parent-id <UUID>` | No | Parent folder. Default: the root. |

A folder created in a shared folder gets its permissions.

### Examples

#### Create a folder in another folder

```bash
passbolt create folder --name "DevOps" --folder-parent-id <PARENT_UUID>
```

## update folder

Rename a folder.

```bash
passbolt update folder --id <UUID> --name <NAME>
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `--id <UUID>` | Yes | ID of the folder. |
| `-n, --name <NAME>` | Yes | New name. |

### Examples

#### Rename a folder

```bash
passbolt update folder --id <UUID> --name "New Name"
```

## delete folder

Delete a folder. Its content moves to the root, unless you delete it too.

```bash
passbolt delete folder --id <UUID> [flags]
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `--id <UUID>` | Yes | ID of the folder. |
| `--cascade` | No | Also delete its sub-folders and the resources in them. |

### Examples

#### Delete a folder and keep its content

```bash
passbolt delete folder --id <UUID>
```

#### Delete a folder with its content

```bash
passbolt delete folder --id <UUID> --cascade
```

## share folder

Give users and groups access to a folder, change their access, or revoke it.

```bash
passbolt share folder --id <UUID> [flags]
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `--id <UUID>` | Yes | ID of the folder. |
| `-t, --type <TYPE>` | No | Permission: `1` (read), `7` (update), `15` (owner) or `-1` (revoke). Default: `1`. |
| `-u, --user <UUID>` | No | User to share with. Repeat it for several. |
| `-g, --group <UUID>` | No | Group to share with. Repeat it for several. |
| `--with-content` | No | Also change the sub-folders and resources you own, as the browser extension does. |

With `--with-content`, the change made on the folder is copied onto the sub-folders and resources
you own: a new access only reaches the items without one, a change or a removal only the items
that have it.

### Examples

#### Make a user owner of a folder

```bash
passbolt share folder --id <UUID> --type 15 --user <USER_UUID>
```

#### Give a group read access to a folder and its content

```bash
passbolt share folder --id <UUID> --type 1 --group <GROUP_UUID> --with-content
```

## move folder

Move a folder into another folder, or to the root.

```bash
passbolt move folder --id <UUID> --folder-parent-id <TARGET_UUID> [flags]
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `--id <UUID>` | Yes | ID of the folder. |
| `-f, --folder-parent-id <UUID>` | No | Destination folder. Empty, or left out, for the root. |
| `--with-folder-permissions` | No | Also change its permissions as for a [resource](resources.md#move-resource), then copy that change onto the content you own (owners only). Needs `--folder-parent-id`. |

### Examples

#### Move a folder

```bash
passbolt move folder --id <UUID> --folder-parent-id <TARGET_UUID>
```

#### Move a folder and take the permissions of the destination

```bash
passbolt move folder --id <UUID> --folder-parent-id <TARGET_UUID> --with-folder-permissions
```

## Related

- [Resources](resources.md): the entries inside the folders.
- [Sharing guide](../../guides/sharing.md): share folders with users and groups.
- [Filters](../filters.md): `--filter` expressions.
