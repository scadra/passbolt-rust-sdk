---
title: Groups
sidebar_position: 5
---

# Groups

## list group

```bash
passbolt list group [OPTIONS]
```

| Option | Description |
|---|---|
| `-u, --user <UUID>` | Groups with one of these members (repeatable) |
| `-m, --manager <UUID>` | Groups with one of these managers (repeatable) |
| `-c, --column <COL>` | Columns: `id`, `name` (default), `created_timestamp`, `modified_timestamp`, `deleted`, `user_count` |
| `--filter <EXPR>` | CEL expression or field condition (see [filters](../filters.md)) |

## get group

Its name, then its members. Columns, headed as written: `UserID`, `Username`, `UserFirstName`,
`UserLastName`, `IsGroupManager`.

```bash
passbolt get group --id <UUID>
passbolt get group --id <UUID> -c Username -c IsGroupManager
```

## create group

```bash
passbolt create group \
  --name "DevOps" \
  --manager <MANAGER_UUID> \
  --user <USER_UUID1> \
  --user <USER_UUID2>
```

At least one `--manager` is required.

## update group

```bash
passbolt update group --id <UUID> --name "New Name" \
  --user <MEMBER_UUID> --manager <MANAGER_UUID>
passbolt update group --id <UUID> --delete --user <USER_UUID> --manager <USER_UUID>
```

`--user` adds a member, or makes a manager a member again; `--manager` adds a manager, or promotes
a member. With `--delete`, the users given are removed instead. Giving a user the role they
already have, or removing a non-member, is refused.

## delete group

```bash
passbolt delete group --id <UUID> --dry-run
passbolt delete group --id <UUID> --transfer-to <USER_UUID>
```

As for [users](users.md#delete-user): what the group alone owns needs a new owner first.
