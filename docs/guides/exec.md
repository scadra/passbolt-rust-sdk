---
title: Injecting secrets
sidebar_position: 4
---

# Injecting secrets with `exec`

Run a command with Passbolt passwords in its environment, without writing them to a file or a
command line.

## Run a command with a secret

Set a variable to `passbolt://<UUID>`, then run the command through `passbolt exec`:

```bash
export DB_PASSWORD="passbolt://a1b2c3d4-e5f6-7890-abcd-ef1234567890"
passbolt exec -- ./deploy.sh
```

`exec` replaces each variable whose value is `passbolt://<UUID>` with the decrypted password of
that resource, and passes the other variables unchanged. See [exec](../cli/commands/exec.md).

- Only the password is injected. A resource without a password gives an empty value.
- A resource that cannot be read stops `exec` before the command starts:
  `Cannot read resource <UUID>`.
- The CLI saves the session keys and logs out before the command starts: a long command does not
  keep a Passbolt session open.
- `exec` exits with the exit code of the command.
- `passbolt exec --debug` names each variable it fills, never its value:

  ```text
  <KEY> env var populated with resource id <ID>
  ```

## Find the UUID of a resource

The UUID is in the first column of `passbolt list resource`. Search by name:

```bash
passbolt list resource --search "Production database" -c id -c name
```

## Why not a file

A secret written to a file (`.env`, `terraform.tfvars`, an inventory) stays on disk after the
command, ends up in backups, and is easy to commit by mistake.

| | A file | `passbolt exec` |
|---|---|---|
| Where the secret lives | On disk, and in the backups of that disk | Only in the memory of the command and of the processes it starts |
| What you commit | The secret, by mistake | `passbolt://<UUID>`, useless without a Passbolt account that can read that resource |
| A password changed in Passbolt | Update the file | Used at the next run: the secret is read when the command starts |
| Who can read it | Anyone who reads the file | Checked by Passbolt, for each run, with the permissions of the user |

:::caution
The environment of a process can still be read by its user and by root (`/proc/<pid>/environ`
on Linux), and every child process inherits it. When that matters, run the command as a user that
nothing else uses.
:::

## Pass a secret to Docker

`docker run --env NAME`, without a value, copies `NAME` from the environment of `docker` itself,
so the secret is not written on the command line:

```bash
export POSTGRES_PASSWORD="passbolt://<UUID>"
passbolt exec -- docker run --rm --env POSTGRES_PASSWORD postgres:16
```

With Compose, list the variable without a value:

```yaml title="compose.yaml"
services:
  app:
    image: example/app:1.4
    environment:
      - DATABASE_PASSWORD
```

```bash
export DATABASE_PASSWORD="passbolt://<UUID>"
passbolt exec -- docker compose up -d
```

`docker inspect` shows the environment of a container: anyone who can run `docker` on the host
can read it.

## Pass a secret to Ansible

A playbook reads the environment with the `env` lookup:

```yaml title="site.yml"
- hosts: db
  tasks:
    - name: Set the application password
      community.postgresql.postgresql_user:
        name: app
        password: "{{ lookup('env', 'APP_DB_PASSWORD') }}"
      no_log: true
```

```bash
export APP_DB_PASSWORD="passbolt://<UUID>"
passbolt exec -- ansible-playbook -i inventory site.yml
```

`no_log: true` keeps the value out of the Ansible output.

## Pass a secret to Terraform

Terraform reads a variable `name` from `TF_VAR_name`:

```hcl
variable "db_password" {
  type      = string
  sensitive = true
}
```

```bash
export TF_VAR_db_password="passbolt://<UUID>"
passbolt exec -- terraform plan
passbolt exec -- terraform apply
```

`sensitive = true` hides the value in the plan. Terraform still writes the values it manages to
its state: keep the state in a backend that encrypts it and restricts access.

Providers that read their own variables work the same way:

```bash
export AWS_ACCESS_KEY_ID="<ACCESS_KEY_ID>"   # an identifier, not a secret
export AWS_SECRET_ACCESS_KEY="passbolt://<UUID>"
passbolt exec -- terraform apply
```

## Connect a database client

PostgreSQL reads `PGPASSWORD`, MySQL and MariaDB `MYSQL_PWD`:

```bash
export PGPASSWORD="passbolt://<UUID>"
passbolt exec -- psql -h db.example.com -U app -d app

export MYSQL_PWD="passbolt://<UUID>"
passbolt exec -- mysql -h db.example.com -u app app
```

The password is not on the command line, where `ps` would show it.

Avoid `passbolt exec -- mysql -p"$MYSQL_PWD"`: the shell expands `$MYSQL_PWD` to
`passbolt://<UUID>` before `exec` runs.

## Inject several secrets

Set as many variables as you need; `exec` replaces all of them:

```bash
export DB_PASSWORD="passbolt://<UUID_1>"
export SMTP_PASSWORD="passbolt://<UUID_2>"
export API_TOKEN="passbolt://<UUID_3>"
passbolt exec -- ./start.sh
```

To set a variable for one command only:

```bash
DB_PASSWORD="passbolt://<UUID>" passbolt exec -- ./migrate.sh
```

## Next steps

- [exec](../cli/commands/exec.md): the command and its flags.
- [CI pipelines](ci.md): use `exec` in GitHub Actions and GitLab CI.
- [Rotating a password](rotation.md): change a password that `exec` hands out.
