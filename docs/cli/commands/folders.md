---
title: Folders
sidebar_position: 3
---

# Folders

## list folder

```bash
passbolt list folder [OPTIONS]
```

Options: `-s/--search`, `-f/--folder` (parent), `-g/--group` (repeatable: folders shared with any
of the groups), `-c/--column` (default `id`, `folder_parent_id`, `name`), `--filter`.

## get folder

```bash
passbolt get folder --id <UUID>
```

## get folder permission

The same columns as [get resource permission](resources.md#get-resource-permission).

```bash
passbolt get folder permission --id <UUID>
```

## create folder

```bash
passbolt create folder --name "DevOps" --folder-parent-id <PARENT_UUID>
```

A folder created in a shared folder gets its permissions.

## update folder

```bash
passbolt update folder --id <UUID> --name "New Name"
```

## delete folder

```bash
passbolt delete folder --id <UUID>             # its content moves to the root
passbolt delete folder --id <UUID> --cascade   # its content is deleted too
```

## share folder

```bash
passbolt share folder --id <UUID> --type 15 --user <UUID>
passbolt share folder --id <UUID> --type 1 --group <UUID> --with-content
```

With `--with-content`, the change made on the folder is copied onto the sub-folders and resources
the user owns, as the browser extension does: a new access only reaches the items without one, a
change or a removal only the items that have it.

## move folder

```bash
passbolt move folder --id <UUID> --folder-parent-id <TARGET_UUID>
passbolt move folder --id <UUID> --folder-parent-id <TARGET_UUID> --with-folder-permissions
```
