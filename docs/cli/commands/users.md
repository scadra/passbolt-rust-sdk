---
title: Users
sidebar_position: 4
---

# Users

List, read, create, change and delete the users of your organization.

## list user

List the users. Alias: `list users`.

```bash
passbolt list user [flags]
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `-g, --group <UUID>` | No | Only the members of one of these groups. Repeat it for several. |
| `-r, --resource <UUID>` | No | Only the users with access to this resource. |
| `-s, --search <TEXT>` | No | Search by name or email. |
| `-a, --admin` | No | Only the administrators. |
| `-c, --column <COLUMN>` | No | Columns to show. Repeat it for several. Default: `id`, `username`, `first_name`, `last_name`, `role`. Also: `created_timestamp`, `modified_timestamp`, `active`, `deleted`, `disabled`. |
| `--filter <EXPR>` | No | A CEL expression or a field condition. See [filters](../filters.md). |

### Examples

#### List the administrators

```bash
passbolt list user --admin
```

#### List who can read a resource

```bash
passbolt list user --resource <RESOURCE_UUID> -c username -c role
```

## get user

Show the username, first name, last name and role of a user.

```bash
passbolt get user --id <UUID>
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `--id <UUID>` | Yes | ID of the user. |

### Examples

#### Read a user as JSON

```bash
passbolt get user --id <UUID> --json
```

## create user

Invite a user to the organization.

```bash
passbolt create user --username <EMAIL> --firstname <NAME> --lastname <NAME> [flags]
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `-u, --username <EMAIL>` | Yes | Email address of the user. |
| `-f, --firstname <NAME>` | Yes | First name. |
| `-l, --lastname <NAME>` | Yes | Last name. |
| `-r, --role <ROLE>` | No | `user` or `admin`. Default: `user`. |

### Examples

#### Invite a user

```bash
passbolt create user \
  --username alice@example.com \
  --firstname Alice \
  --lastname Martin \
  --role user
```

## update user

Change the name or the role of a user.

```bash
passbolt update user --id <UUID> [flags]
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `--id <UUID>` | Yes | ID of the user. |
| `-f, --firstname <NAME>` | No | New first name. |
| `-l, --lastname <NAME>` | No | New last name. |
| `-r, --role <ROLE>` | No | New role: `user` or `admin`. |

### Examples

#### Change the last name and make the user an administrator

```bash
passbolt update user --id <UUID> --lastname "Dupont" --role admin
```

## delete user

Delete a user (administrators). What the user alone owns or manages blocks the deletion until
you give it to someone else.

```bash
passbolt delete user --id <UUID> [flags]
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `--id <UUID>` | Yes | ID of the user. |
| `--dry-run` | No | Only list what blocks the deletion. Cannot be used with `--transfer-to`. |
| `--transfer-to <UUID>` | No | User or group that becomes owner of what the user alone owns, and manager of the groups they alone manage. They must already have access to it. |

A user who alone owns shared resources or folders, or alone manages groups, is deleted only once
someone takes them over. Without `--transfer-to`, the command fails with:

```text
The user alone owns <N> resources and <N> folders and alone manages <N> groups: give them to someone with --transfer-to <user or group id> (list them with --dry-run)
```

### Examples

#### See what blocks the deletion

```bash
passbolt delete user --id <UUID> --dry-run
```

#### Give the user's resources to another user, then delete them

```bash
passbolt delete user --id <UUID> --transfer-to <USER_UUID>
```

## Related

- [Groups](groups.md): the same deletion rules apply to groups.
- [Filters](../filters.md): `--filter` expressions.
- [Troubleshooting](../troubleshooting.md): errors when deleting a user.
