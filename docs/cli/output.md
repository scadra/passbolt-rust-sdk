---
title: Output
sidebar_position: 5
---

# Output

Read what the commands print: tables, key-value lines, or JSON for scripts.

## Tables

`list` and the permissions print a table: the column names as headers, every cell padded to its
column, ` | ` between cells, then an empty line.

```bash
passbolt list resource
```

```text
id                                   | folder_parent_id | name   | username     | uri
a1b2c3d4-e5f6-7890-abcd-ef1234567890 |                  | GitHub | alice        | https://github.com
b2c3d4e5-f6a7-8901-bcde-f12345678901 |                  | AWS    | ops@corp.com |
```

- A line break in a value continues the cell on the next line, in its column.
- Control characters are removed from the cells, so a resource name cannot send escape
  sequences to your terminal.

### Choose the columns

`-c, --column` chooses the columns. Repeat it for several. Column names are read in any case and
also in camelCase (`FolderParentID`, `CreatedTimestamp`…).

```bash
passbolt list resource -c name -c uri
```

## JSON

`--json` prints JSON indented by two spaces; for `list`, an array of the items:

- Each item with its fields.
- Dates in UTC: `2024-01-01T10:00:00Z`.
- An empty `folder_parent_id` for an item at the root.
- With `-c`, only those fields.

```bash
passbolt list resource --json | jq '.[].name'
passbolt list user -c username -c role --json
```

## Key-value

`get` without `--json` prints one `Key: value` line per field:

```bash
passbolt get resource --id <UUID>
```

```text
FolderParentID:
Name: GitHub
Username: alice
URI: https://github.com
Password: s3cr3t
Description:
```

`get resource` then shows the other metadata fields, and what only the secret holds: note, PIN
code, TOTP, custom fields, expiry.

## Writes

| Command | Without `--json` | With `--json` |
|---|---|---|
| `create` | `ResourceID: <id>` (or `FolderID`, `UserID`, `GroupID`) | `{"id": …}` |
| `update`, `delete`, `share`, `move` | Nothing | `{"id": …, "result": …}` |

## Related

- [Filters](filters.md): keep only the rows you want.
- [Commands](commands/README.md): the columns of each `list`.
- [Scripting guide](../guides/scripting.md): JSON output in scripts.
