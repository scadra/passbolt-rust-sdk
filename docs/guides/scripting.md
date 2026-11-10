---
title: Scripting
sidebar_position: 3
---

# Scripting

With `--json`, every command prints JSON on stdout, and prompts, warnings and errors go to
stderr. [jq](https://jqlang.github.io/jq/) then picks the fields. The fields are those of
[output](../cli/output.md).

Each script below starts with:

```bash
#!/usr/bin/env bash
set -euo pipefail
```

`-e` stops the script at the first command that fails, `-u` at the first unset variable, and
`pipefail` makes a pipeline fail when `passbolt` fails, not only when `jq` does.

The examples assume a saved configuration (see [quick start](../getting-started/quick-start.md))
or the `PASSBOLT_*` variables of [CI pipelines](ci.md). Each command logs in once: a script that
runs many commands with an account with MFA needs `noninteractive-totp`.

## Find a resource by name and read its password

`--search` matches part of the name, in any case. `jq` then keeps the exact name:

```bash
name="Production database"

id=$(passbolt list resource --search "$name" --json \
  | jq -r --arg name "$name" '[.[] | select(.name == $name)] | if length == 1 then .[0].id else empty end')

if [[ -z "$id" ]]; then
  echo "No single resource named \"$name\"" >&2
  exit 1
fi

password=$(passbolt get resource --id "$id" --json | jq -r .password)
```

`get resource --json` holds `name`, `username`, `uri`, `password`, `description`,
`folder_parent_id`, and `metadata` and `secret` with every field of the resource. To see which
fields a resource holds, without printing their values:

```bash
passbolt get resource --id "$id" --json | jq '{metadata: (.metadata | keys), secret: (.secret | keys)}'
```

To hand the password to a program, [`passbolt exec`](exec.md) avoids holding it in a shell
variable at all.

## List the passwords that expire soon

`expired` is true for a resource with an expiry date, and `expired_at` is that date. `--filter`
takes a [CEL](../cli/filters.md) expression; CEL has no clock, so the shell gives the date:

```bash
limit=$(date -u -d '+30 days' +%Y-%m-%dT%H:%M:%SZ)   # GNU date; on macOS: date -u -v+30d …

passbolt list resource \
  --filter "expired && expired_at < timestamp(\"$limit\")" \
  -c id -c name -c expired_at --json \
  | jq -r '.[] | "\(.expired_at)  \(.name)  \(.id)"'
```

The passwords already expired:

```bash
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
passbolt list resource --filter "expired && expired_at < timestamp(\"$now\")" -c id -c name
```

A filter that matches nothing is an error (`no such resources found with filter …`, exit code 1).
In a script, tell it apart from a real failure:

```bash
if ! result=$(passbolt list resource --filter "expired && expired_at < timestamp(\"$now\")" \
    -c id -c name --json 2> error.log); then
  if grep -q '^Error: no such resources found' error.log; then
    result='[]'
  else
    cat error.log >&2
    exit 1
  fi
fi
```

`--search` with no match is not an error: it prints `[]`.

## Loop over resources

Read the IDs with `jq -r`, one per line, then loop with `while read`:

```bash
passbolt list resource --folder "$FOLDER_ID" -c id -c name --json \
  | jq -r '.[] | [.id, .name] | @tsv' \
  | while IFS=$'\t' read -r id name; do
      echo "Checking $name"
      passbolt get resource permission --id "$id" --json \
        | jq -r '.[] | "\(.aro) \(.aro_foreign_key) \(.type)"'
    done
```

Each `passbolt` call logs in again. To read many resources, one `list resource` with the columns
needed is faster than a `get resource` per resource: `-c password` decrypts the passwords in the
list.

```bash
passbolt list resource --folder "$FOLDER_ID" -c name -c username -c password --json \
  | jq -r '.[] | [.name, .username] | @tsv'
```

Other lists work the same way:

```bash
passbolt list user --filter 'role == "admin"' -c username --json | jq -r '.[].username'
passbolt list group -c id -c name -c user_count --json | jq -r '.[] | select(.user_count == 0) | .name'
```

## Write and keep the ID

`create` prints `{"id": …}` with `--json`:

```bash
folder_id=$(passbolt create folder --name "Release 2026" --json | jq -r .id)
passbolt create resource --name "Registry token" --folder-parent-id "$folder_id" --generate --json \
  | jq -r .id
```

## Exit codes

- `0`: success.
- `1`: any error, usage errors included. The message is on stderr: `Error: <message>`.
- `passbolt exec` exits with the exit code of the command it ran.

A failed command prints nothing on stdout, so `jq` reads no input; with `pipefail`, the pipeline
still fails with the code of `passbolt`.

```bash
if ! passbolt get resource --id "$id" --json > resource.json; then
  echo "Cannot read resource $id" >&2
  exit 1
fi
```

A file holding a secret should be readable by its owner only: run `umask 077` first, and remove
it when done. Better, keep secrets in variables or use `passbolt exec`.
