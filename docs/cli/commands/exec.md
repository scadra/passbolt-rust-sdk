---
title: exec
sidebar_position: 6
---

# exec

Run a command with Passbolt secrets in its environment.

Any environment variable holding a `passbolt://<UUID>` URI is replaced with the decrypted password
of that resource before the command starts; the command inherits all the other variables.

```bash
# The clients read their password from these variables.
export PGPASSWORD="passbolt://a1b2c3d4-e5f6-7890-abcd-ef1234567890"
export MYSQL_PWD="passbolt://a1b2c3d4-e5f6-7890-abcd-ef1234567890"

passbolt exec -- psql -U myuser -d mydb
passbolt exec -- mysql -u root
passbolt exec -- ansible-playbook site.yml
```

The command must read the variable itself: in `mysql -p"$DB_PASSWORD"`, your shell expands the
variable before `exec` runs, and the command gets the `passbolt://` URI, not the password. See
the [exec guide](../../guides/exec.md) for Docker, Ansible and Terraform.

With `--debug`, each replaced variable is named on stdout (`<KEY> env var populated with
resource id <ID>`), never its value.
