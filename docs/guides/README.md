---
title: Guides
sidebar_position: 1
---

# Guides

Tasks done with the `passbolt` CLI, from start to end. The options of each command are in
[commands](../cli/commands/README.md).

- [CI pipelines](ci.md): run the CLI in GitHub Actions and GitLab CI, with a dedicated account.
- [Scripting](scripting.md): `--json`, `jq`, `--filter` and exit codes in shell scripts.
- [Injecting secrets](exec.md): give secrets to Docker, Ansible, Terraform or a database client
  with `passbolt exec`.
- [Rotating a password](rotation.md): generate a password, update the service, set an expiry.
- [Backups](backup.md): scheduled KeePass and CSV exports, and how to restore them.
- [Migration](migration.md): move from another password manager with `passbolt import`.
- [Sharing](sharing.md): users, groups, folders, and ownership before deleting a user.
