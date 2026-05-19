---
title: Filters and expiry
sidebar_position: 6
---

# Filters and expiry

## `--filter`

`--filter` takes a [CEL](https://github.com/google/cel-spec) expression over the columns of the
list (see `-c`), as go-passbolt-cli does, with their types: text, booleans (`deleted`,
`expired`, `personal`, `active`, `disabled`), numbers (`user_count`), timestamps
(`created_timestamp`, `modified_timestamp`, `expired_at`) and maps (`metadata`, `secret`).

```bash
passbolt list resource --filter '(name == "GitHub" || matches(name, "^AWS")) && uri.startsWith("https://")'
passbolt list user --filter 'role == "admin" && created_timestamp > timestamp("2024-01-01T00:00:00Z")'
passbolt list resource --filter '"Account" in secret' -c name
passbolt list group --filter 'user_count > 2'
```

A filter that matches nothing is an error: `no such resources found with filter …`. A filter
reading `password`, `description` or `secret` decrypts the secrets.

### Field conditions

Field conditions are accepted too, and several `--filter` are ANDed:

| Operator | Meaning | Example |
|---|---|---|
| `field=value` | Exact match (case-insensitive) | `--filter "role=admin"` |
| `field~=value` | Contains | `--filter "name~=github"` |
| `field^=value` | Starts with | `--filter "username^=john"` |
| `field$=value` | Ends with | `--filter "uri$=.com"` |
| `field!=value` | Not equal | `--filter "username!=admin"` |

A text that is valid CEL is read as CEL; `name != "x"` is CEL, `name!=x` a field condition. The
first operator written splits a field condition: `uri=https://a/?x!=y` is `uri` equal to
`https://a/?x!=y`.

## Expiry dates

`--expiry`, for `create resource` and `update resource`:

| Value | Meaning |
|---|---|
| `"2025-12-31T00:00:00Z"` | Absolute date (RFC3339), sent in UTC |
| `"90d"`, `"2w"`, `"1w2d3h"` | From now, in weeks, days, hours, minutes, seconds |
| `"1.5h"`, `"300ms"`, `"2h45m30.5s"` | From now, as a Go duration |
| `"-1h"` | In the past: already expired |
| `"none"` or `""` | Remove expiry |

```bash
passbolt create resource --name "Temp token" --expiry "7d"
passbolt update resource --id <UUID> --expiry "none"
```
