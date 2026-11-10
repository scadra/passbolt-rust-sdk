---
title: Injecting secrets
sidebar_position: 4
---

# Injecting secrets with `exec`

`passbolt exec` runs a command with Passbolt passwords in its environment. Each variable whose
value is `passbolt://<UUID>` is replaced with the decrypted password of that resource; the other
variables are passed unchanged. See [exec](../cli/commands/exec.md).

```bash
export DB_PASSWORD="passbolt://a1b2c3d4-e5f6-7890-abcd-ef1234567890"
passbolt exec -- ./deploy.sh
```

- Only the password is injected. A resource without a password gives an empty value.
- A resource that cannot be read stops `exec` before the command starts:
  `Cannot read resource <UUID>`.
- The CLI saves the session keys and logs out before the command starts: a long command does not
  keep a Passbolt session open.
- `exec` exits with the exit code of the command.
- `passbolt exec --debug` prints `<KEY> env var populated with resource id <ID>` for each
  variable, never its value.

The UUID of a resource is in the first column of `passbolt list resource`, or:

```bash
passbolt list resource --search "Production database" -c id -c name
```

## Why not a file

A secret written to a file (`.env`, `terraform.tfvars`, an inventory) stays on disk after the
command, ends up in backups, and is easy to commit by mistake. With `exec`:

- the secret exists only in the memory of the command and of the processes it starts;
- the file committed holds `passbolt://<UUID>`, which is useless without a Passbolt account that
  can read that resource;
- the secret is read when the command starts: a password changed in Passbolt is used at the next
  run, with nothing to update;
- access is checked by Passbolt, for each run, with the permissions of the user.

The environment of a process can still be read by its user and by root (`/proc/<pid>/environ`
on Linux), and is inherited by every child process. Run the command as a user that nothing else
uses when that matters.

## Docker

`docker run --env NAME`, without a value, copies `NAME` from the environment of `docker` itself:
the secret is not written on the command line.

```bash
export POSTGRES_PASSWORD="passbolt://<UUID>"
passbolt exec -- docker run --rm --env POSTGRES_PASSWORD postgres:16
```

With Compose, list the variable without a value in `compose.yaml`:

```yaml
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

## Ansible

A playbook reads the environment with the `env` lookup:

```yaml
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

## Terraform

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

## A database client

PostgreSQL reads `PGPASSWORD`, MySQL and MariaDB `MYSQL_PWD`:

```bash
export PGPASSWORD="passbolt://<UUID>"
passbolt exec -- psql -h db.example.com -U app -d app

export MYSQL_PWD="passbolt://<UUID>"
passbolt exec -- mysql -h db.example.com -u app app
```

The password is not given on the command line, where `ps` would show it. Avoid
`passbolt exec -- mysql -p"$MYSQL_PWD"`: the shell expands `$MYSQL_PWD` before `exec` runs, to
`passbolt://<UUID>`.

## Several secrets, one command

Set as many variables as needed; `exec` replaces all of them:

```bash
export DB_PASSWORD="passbolt://<UUID_1>"
export SMTP_PASSWORD="passbolt://<UUID_2>"
export API_TOKEN="passbolt://<UUID_3>"
passbolt exec -- ./start.sh
```

A variable can also be set for one command only:

```bash
DB_PASSWORD="passbolt://<UUID>" passbolt exec -- ./migrate.sh
```
