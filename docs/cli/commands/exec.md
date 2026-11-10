---
title: exec
sidebar_position: 6
---

# exec

Run a command with Passbolt secrets in its environment.

## exec

Replace each environment variable holding a `passbolt://<UUID>` URI with the decrypted password
of that resource, then run the command. The command inherits all the other variables.

```bash
passbolt exec -- <COMMAND> [ARGS...]
```

### Arguments

| Argument | Required | Description |
|---|---|---|
| `<COMMAND> [ARGS...]` | Yes | The command to run and its arguments, after `--`. Without it, the command fails with `No command specified`. |

The command exits with the exit code of the command it ran. The session with the server is
closed before the command starts.

:::caution
The command must read the variable itself. In `mysql -p"$DB_PASSWORD"`, your shell expands the
variable before `exec` runs, and the command gets the `passbolt://` URI, not the password.
:::

With `--debug`, each replaced variable is named on stdout (`<KEY> env var populated with
resource id <ID>`), never its value.

### Examples

#### Connect to PostgreSQL

```bash
export PGPASSWORD="passbolt://<UUID>"
passbolt exec -- psql -U myuser -d mydb
```

#### Connect to MySQL

```bash
export MYSQL_PWD="passbolt://<UUID>"
passbolt exec -- mysql -u root
```

#### Run an Ansible playbook

```bash
passbolt exec -- ansible-playbook site.yml
```

## Related

- [exec guide](../../guides/exec.md): Docker, Ansible and Terraform.
- [Configuration](../configuration.md): `--debug` and the other global flags.
