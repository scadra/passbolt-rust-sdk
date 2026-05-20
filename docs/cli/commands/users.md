---
title: Users
sidebar_position: 4
---

# Users

## list user

```bash
passbolt list user [OPTIONS]
```

| Option | Description |
|---|---|
| `-g, --group <UUID>` | Members of one of these groups (repeatable) |
| `-r, --resource <UUID>` | Users with access to this resource |
| `-s, --search <TEXT>` | Search by name or email |
| `-a, --admin` | Only show admins |
| `-c, --column <COL>` | Columns: `id`, `username`, `first_name`, `last_name`, `role` (default), `created_timestamp`, `modified_timestamp`, `active`, `deleted`, `disabled` |
| `--filter <EXPR>` | CEL expression or field condition (see [filters](../filters.md)) |

## get user

```bash
passbolt get user --id <UUID>
```

## create user

```bash
passbolt create user \
  --username alice@example.com \
  --firstname Alice \
  --lastname Martin \
  --role user       # or "admin"
```

## update user

```bash
passbolt update user --id <UUID> --lastname "Dupont" --role admin
```

## delete user

```bash
passbolt delete user --id <UUID> --dry-run                    # what blocks the deletion
passbolt delete user --id <UUID> --transfer-to <USER_UUID>
```

A user who alone owns shared resources or folders, or alone manages groups, is deleted only once
someone takes them over: `--transfer-to` makes a user (or group) who already has access owner of
each item, and manager of each group they belong to.
