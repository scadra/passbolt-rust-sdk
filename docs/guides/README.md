---
title: Guides
sidebar_position: 1
---

# Guides

Follow a task with the `passbolt` CLI from start to end.

Each guide links to the commands it uses. Every flag of every command is in
[commands](../cli/commands/README.md).

| Guide | What you do |
|---|---|
| [CI pipelines](ci.md) | Run the CLI in GitHub Actions and GitLab CI, with a dedicated account. |
| [Scripting](scripting.md) | Use `--json`, `jq`, `--filter` and exit codes in shell scripts. |
| [Injecting secrets](exec.md) | Give secrets to Docker, Ansible, Terraform or a database client with `passbolt exec`. |
| [Rotating a password](rotation.md) | Generate a password, update the service, set an expiry. |
| [Backups](backup.md) | Schedule KeePass and CSV exports, and restore them. |
| [Migration](migration.md) | Move from another password manager with `passbolt import`. |
| [Sharing](sharing.md) | Share with users, groups and folders, and transfer ownership before deleting a user. |

## Related

- [Quick start](../getting-started/quick-start.md): connect the CLI to your server.
- [Configuration](../cli/configuration.md): every setting and its environment variable.
