---
title: Groups
sidebar_position: 5
---

# Groups

List, read, create, change and delete the groups of your organization.

## list group

List the groups. Alias: `list groups`.

```bash
passbolt list group [flags]
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `-u, --user <UUID>` | No | Only the groups with this member. Repeat it for several. |
| `-m, --manager <UUID>` | No | Only the groups with this manager. Repeat it for several. |
| `-c, --column <COLUMN>` | No | Columns to show: `id`, `name`, `created_timestamp`, `modified_timestamp`, `deleted`, `user_count`. Default: `id`, `name`. |
| `--filter <EXPR>` | No | A CEL expression or a field condition. See [filters](../filters.md). |

### Examples

#### List the groups you manage

```bash
passbolt list group --manager <USER_UUID>
```

#### List the groups with more than two members

```bash
passbolt list group --filter 'user_count > 2' -c name -c user_count
```

## get group

Show the name of a group, then its members.

```bash
passbolt get group --id <UUID> [flags]
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `--id <UUID>` | Yes | ID of the group. |
| `-c, --column <COLUMN>` | No | Columns of the members, headed as written: `UserID`, `Username`, `UserFirstName`, `UserLastName`, `IsGroupManager`. |

### Examples

#### Show who manages a group

```bash
passbolt get group --id <UUID> -c Username -c IsGroupManager
```

## create group

Create a group with its managers and members.

```bash
passbolt create group --name <NAME> --manager <UUID> [flags]
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `-n, --name <NAME>` | Yes | Name of the group. |
| `-m, --manager <UUID>` | Yes | Manager of the group. Repeat it for several. |
| `-u, --user <UUID>` | No | Member of the group. Repeat it for several. |

### Examples

#### Create a group with two members

```bash
passbolt create group \
  --name "DevOps" \
  --manager <MANAGER_UUID> \
  --user <USER_UUID1> \
  --user <USER_UUID2>
```

## update group

Rename a group, or add and remove its members and managers.

```bash
passbolt update group --id <UUID> [flags]
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `--id <UUID>` | Yes | ID of the group. |
| `-n, --name <NAME>` | No | New name. |
| `-u, --user <UUID>` | No | Add this member, or turn this manager back into a member. Repeat it for several. |
| `-m, --manager <UUID>` | No | Add this manager, or promote this member. Repeat it for several. |
| `-d, --delete` | No | Remove the users given with `--user` and `--manager` instead. |

:::note
Giving a user the role they already have, or removing someone who is not a member, is refused.
:::

### Examples

#### Rename a group and add a manager

```bash
passbolt update group --id <UUID> --name "Platform" --manager <MANAGER_UUID>
```

#### Remove a member and a manager

```bash
passbolt update group --id <UUID> --delete --user <USER_UUID> --manager <MANAGER_UUID>
```

## delete group

Delete a group. What the group alone owns blocks the deletion until you give it a new owner.

```bash
passbolt delete group --id <UUID> [flags]
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `--id <UUID>` | Yes | ID of the group. |
| `--dry-run` | No | Only list what blocks the deletion. |
| `--transfer-to <UUID>` | No | User or group that becomes the owner of what the group alone owns. They must already have access to it. |

### Examples

#### See what blocks the deletion

```bash
passbolt delete group --id <UUID> --dry-run
```

#### Give the group's resources to a user, then delete it

```bash
passbolt delete group --id <UUID> --transfer-to <USER_UUID>
```

## Related

- [Users](users.md): the same deletion rules apply to users.
- [Sharing guide](../../guides/sharing.md): share with a group.
- [Filters](../filters.md): `--filter` expressions.
