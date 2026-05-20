---
title: exec
sidebar_position: 6
---

# exec

Run a command with Passbolt secrets in its environment.

Any environment variable holding a `passbolt://<UUID>` URI is replaced with the decrypted password
of that resource before the command starts; the command inherits all the other variables.

```bash
export DB_PASSWORD="passbolt://a1b2c3d4-e5f6-7890-abcd-ef1234567890"

passbolt exec -- psql -U myuser -d mydb
passbolt exec -- mysql -u root -p"$DB_PASSWORD"
passbolt exec -- ansible-playbook site.yml
```

With `--debug`, each replaced variable is named on stderr (`<KEY> env var populated with
resource id <ID>`), never its value.
