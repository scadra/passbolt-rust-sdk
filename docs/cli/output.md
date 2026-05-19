---
title: Output
sidebar_position: 5
---

# Output

The output is go-passbolt-cli's, so that scripts written for it keep working.

## Tables

The default for `list` and permissions: every cell padded to its column, ` | ` between cells,
the column names as headers, then an empty line.

```text
id                                   | folder_parent_id | name   | username     | uri
a1b2c3d4-e5f6-7890-abcd-ef1234567890 |                  | GitHub | alice        | https://github.com
b2c3d4e5-f6a7-8901-bcde-f12345678901 |                  | AWS    | ops@corp.com |
```

`-c/--column` chooses the columns (repeatable), in any case and in go-passbolt-cli's spellings
(`FolderParentID`, `CreatedTimestamp`…).

## JSON

`--json`: each item with go-passbolt-cli's fields, dates in UTC (`2024-01-01T10:00:00Z`), an empty
`folder_parent_id` at the root; with `-c`, only those fields.

```bash
passbolt list resource --json | jq '.[].name'
passbolt list user -c username -c role --json
```

## Key-value

`get` without `--json`:

```text
FolderParentID:
Name: GitHub
Username: alice
URI: https://github.com
Password: s3cr3t
Description:
```

`get resource` then shows the other metadata fields, and what only the secret holds (note, PIN
code, TOTP, custom fields, expiry).

## Writes

`create` prints `ResourceID: <id>` (`FolderID`, `UserID`, `GroupID`), or `{"id": …}` with
`--json`; `update`, `delete`, `share` and `move` print nothing, or `{"id": …, "result": …}` with
`--json`.
