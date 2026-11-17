---
title: migrate-metadata
sidebar_position: 10
---

# migrate-metadata

Upgrade the v4 resources to v5, so that their name, username, URI and description get encrypted.

## migrate-metadata

Encrypt the metadata of the v4 resources (administrators). A resource only one user can read gets
metadata personal to that user, when the settings allow personal keys; the others get the shared
metadata key.

```bash
passbolt migrate-metadata [flags]
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `--shared-only` | No | Upgrade only the resources shared with other users or groups. |

### Examples

#### Upgrade every v4 resource

```bash
passbolt migrate-metadata
```

#### Upgrade only the shared resources

```bash
passbolt migrate-metadata --shared-only
```

## Related

- [Resources](resources.md): the resource types and their metadata.
