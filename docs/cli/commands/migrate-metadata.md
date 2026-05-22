---
title: migrate-metadata
sidebar_position: 10
---

# migrate-metadata

Upgrade the v4 resources to v5 (administrators): their name, username, URI and description get
encrypted. A resource only one user can read gets metadata personal to that user, when the
settings allow personal keys; the others the shared metadata key.

```bash
passbolt migrate-metadata
passbolt migrate-metadata --shared-only
```
