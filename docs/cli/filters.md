---
title: Filters and expiry
sidebar_position: 6
---

# Filters and expiry

Keep only the rows you want in a `list` with `--filter`, and set when a resource expires with
`--expiry`.

## `--filter`

`--filter` takes a [CEL](https://github.com/google/cel-spec) expression over the columns of the
list (see `-c`). The columns keep their types:

| Type | Columns |
|---|---|
| Text | The other columns: `name`, `username`, `uri`, `role`… |
| Boolean | `deleted`, `expired`, `personal`, `active`, `disabled` |
| Number | `user_count` |
| Timestamp | `created_timestamp`, `modified_timestamp`, `expired_at` |
| Map | `metadata`, `secret` |

- Several `--filter` are ANDed.
- A filter that matches nothing is an error: `no such resources found with filter …`.
- A filter reading `password`, `description` or `secret` decrypts the secrets.

### Examples

#### Match a name, then check the URI

```bash
passbolt list resource --filter '(name == "GitHub" || matches(name, "^AWS")) && uri.startsWith("https://")'
```

#### List the administrators created since a date

```bash
passbolt list user --filter 'role == "admin" && created_timestamp > timestamp("2024-01-01T00:00:00Z")'
```

#### List the resources whose secret has a field

```bash
passbolt list resource --filter '"Account" in secret' -c name
```

#### List the groups with more than two members

```bash
passbolt list group --filter 'user_count > 2'
```

### Field conditions

`--filter` also takes field conditions. They compare text, case-insensitively:

| Operator | Meaning | Example |
|---|---|---|
| `field=value` | Exact match | `--filter "role=admin"` |
| `field~=value` | Contains | `--filter "name~=github"` |
| `field^=value` | Starts with | `--filter "username^=john"` |
| `field$=value` | Ends with | `--filter "uri$=.com"` |
| `field!=value` | Not equal | `--filter "username!=admin"` |

How the CLI tells them apart:

- A text that is valid CEL is read as CEL: `name != "x"` is CEL, `name!=x` a field condition.
- The first operator written splits a field condition: `uri=https://a/?x!=y` is `uri` equal to
  `https://a/?x!=y`.
- A field condition reading `note` also decrypts the secrets.

## Expiry dates

`--expiry` sets when a resource expires, for `create resource` and `update resource`:

| Value | Meaning |
|---|---|
| `"2025-12-31T00:00:00Z"` | Absolute date (RFC3339), sent in UTC. |
| `"90d"`, `"2w"`, `"1w2d3h"` | From now, in weeks, days, hours, minutes, seconds. |
| `"1.5h"`, `"300ms"`, `"2h45m30.5s"` | From now, as a Go duration. |
| `"-1h"` | In the past: already expired. |
| `"none"` or `""` | Remove the expiry. |

### Examples

#### Create a resource that expires in a week

```bash
passbolt create resource --name "Temp token" --expiry "7d"
```

#### Remove the expiry

```bash
passbolt update resource --id <UUID> --expiry "none"
```

#### Mark a resource as expired

```bash
passbolt update resource --id <UUID> --expiry=-1h
```

:::note
A negative value needs the `=` form: `--expiry=-1h`.
:::

## Related

- [Output](output.md): columns, tables and JSON.
- [Resources](commands/resources.md): `list resource`, `create resource`, `update resource`.
- [Rotation guide](../guides/rotation.md): find what to rotate and set a new expiry.
