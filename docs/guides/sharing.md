---
title: Sharing
sidebar_position: 8
---

# Sharing

A resource or a folder is shared with users and groups, each with a permission. The commands
take IDs: find them first.

```bash
passbolt list user --search alice -c id -c username
passbolt list user --filter 'username == "alice@example.com"' -c id --json | jq -r '.[0].id'
passbolt list group --filter 'name == "DevOps"' -c id --json | jq -r '.[0].id'
passbolt list resource --search "Staging database" -c id -c name
passbolt list folder --search "Infrastructure" -c id -c name
```

## Permissions

| `--type` | Permission | Allows |
|---|---|---|
| `1` | read | read the secret |
| `7` | update | read and edit |
| `15` | owner | read, edit, share, delete |
| `-1` | — | remove the access of the users and groups given |

`share` changes only the users and groups given; the others keep their access. `--type` is `1`
when left out. A resource always keeps at least one owner.

## Sharing a resource

```bash
passbolt share resource --id <UUID> --type 1 --user <USER_UUID>
passbolt share resource --id <UUID> --type 7 --group <GROUP_UUID>
passbolt share resource --id <UUID> --type 7 --user <USER_UUID_1> --user <USER_UUID_2> --group <GROUP_UUID>
passbolt share resource --id <UUID> --type -1 --user <USER_UUID>
```

Sharing again with another `--type` changes the permission. Revoking a user or group without
access fails before anything changes.

Who has access:

```bash
passbolt get resource permission --id <UUID>
passbolt get resource permission --id <UUID> --json | jq -r '.[] | "\(.aro) \(.aro_foreign_key) \(.type)"'
passbolt list user --resource <UUID> -c username -c first_name -c last_name
```

`aro` is `User` or `Group`, `aro_foreign_key` its ID, `type` the number of the table above.

## Folders

A folder carries permissions too. They reach what is inside it in three cases:

- A resource or folder **created** in a shared folder gets the permissions of that folder:

  ```bash
  passbolt create resource --name "Staging database" --folder-parent-id <FOLDER_UUID> --generate
  passbolt create folder --name "Staging" --folder-parent-id <FOLDER_UUID>
  ```

- A folder **shared** with `--with-content` copies the change onto the sub-folders and resources
  inside that you own, as the browser extension does. A new access only reaches the items without
  one; a change or a removal only the items that have it:

  ```bash
  passbolt share folder --id <FOLDER_UUID> --type 7 --group <GROUP_UUID> --with-content
  passbolt share folder --id <FOLDER_UUID> --type -1 --user <USER_UUID> --with-content
  ```

  Without `--with-content`, only the folder itself changes: the members see the folder, but not
  the items they had no access to.

- An item **moved** with `--with-folder-permissions` loses the permissions it got from the folder
  it leaves and gets those of the destination, the higher level winning. Only an owner can:

  ```bash
  passbolt move resource --id <UUID> --folder-parent-id <FOLDER_UUID> --with-folder-permissions
  passbolt move folder --id <FOLDER_UUID> --folder-parent-id <TARGET_UUID> --with-folder-permissions
  ```

  A plain `move` keeps the permissions as they were.

Afterwards, the permissions of each item are its own: sharing an item inside a folder does not
change the folder, and a later change of the folder needs `--with-content` again.

```bash
passbolt get folder permission --id <FOLDER_UUID>
```

## A group for a team

Share with a group rather than with each person: someone who joins or leaves the team is added to
or removed from the group, and every resource follows.

```bash
lead=$(passbolt list user --filter 'username == "lead@example.com"' -c id --json | jq -r '.[0].id')
alice=$(passbolt list user --filter 'username == "alice@example.com"' -c id --json | jq -r '.[0].id')
bob=$(passbolt list user --filter 'username == "bob@example.com"' -c id --json | jq -r '.[0].id')

group=$(passbolt create group --name "DevOps" --manager "$lead" --user "$alice" --user "$bob" --json \
  | jq -r .id)

folder=$(passbolt create folder --name "DevOps" --json | jq -r .id)
passbolt share folder --id "$folder" --type 7 --group "$group" --with-content
```

A group needs at least one manager. Managers add and remove members:

```bash
passbolt update group --id "$group" --user <NEW_MEMBER_UUID>          # add a member
passbolt update group --id "$group" --manager <USER_UUID>             # add a manager, or promote
passbolt update group --id "$group" --delete --user <LEAVER_UUID>     # remove a member
passbolt get group --id "$group"                                      # members and managers
```

The resources shared with the group:

```bash
passbolt list resource --group "$group" -c name -c username
```

## Transferring ownership before deleting a user

A user who alone owns shared resources or folders, or alone manages a group, cannot be deleted
until someone takes them over. See what blocks the deletion:

```bash
passbolt delete user --id <USER_UUID> --dry-run
passbolt delete user --id <USER_UUID> --dry-run --json
```

```text
resource 5f1c… is only owned by the user
folder 8a2d… is only owned by the user
group 3b4e… (DevOps) is only managed by the user
group 9c0f… has no other member: deleted with the user
```

`--transfer-to` then makes another user owner of each of those items and manager of each of
those groups, and deletes the user:

```bash
passbolt delete user --id <USER_UUID> --transfer-to <SUCCESSOR_UUID>
```

The successor must already have access to each item and belong to each group; otherwise the
command fails and names the item (`… has no access to the resource …: share it with them first`).
Give them access first, while the leaving user still owns the items:

```bash
passbolt share resource --id <RESOURCE_UUID> --type 7 --user <SUCCESSOR_UUID>
passbolt share folder --id <FOLDER_UUID> --type 7 --user <SUCCESSOR_UUID> --with-content
passbolt update group --id <GROUP_UUID> --user <SUCCESSOR_UUID>
```

Only an owner can share an item: since the leaving user alone owns these items, the shares are
made with their account, before they leave. Then run `--dry-run` again, and the deletion.

`--transfer-to` also takes a group that already has access to the items; groups to manage still
need a user. Deleting a group works the same way:

```bash
passbolt delete group --id <GROUP_UUID> --dry-run
passbolt delete group --id <GROUP_UUID> --transfer-to <USER_UUID>
```
