---
title: Rotating a password
sidebar_position: 5
---

# Rotating a password

Find the passwords to change, generate new ones, update the service and Passbolt, and set the
next expiry date.

The order matters: until both the service and Passbolt hold the new password, keep a way back to
the old one.

## 1. Find what to rotate

List the resources whose expiry date has passed (see [filters](../cli/filters.md)):

```bash
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
passbolt list resource --filter "expired && expired_at < timestamp(\"$now\")" \
  -c id -c name -c username -c expired_at
```

List those that expire within two weeks:

```bash
soon=$(date -u -d '+14 days' +%Y-%m-%dT%H:%M:%SZ)
passbolt list resource --filter "expired && expired_at < timestamp(\"$soon\")" -c id -c name -c expired_at
```

`expired` is true for every resource with an expiry date, past or future; `expired_at` is the
date. A filter that matches nothing exits with `Error: no such resources found with filter …`
(see [scripting](scripting.md#list-the-passwords-that-expire-soon)).

List the resources not changed for a year, whatever their expiry:

```bash
year_ago=$(date -u -d '-1 year' +%Y-%m-%dT%H:%M:%SZ)
passbolt list resource --filter "modified_timestamp < timestamp(\"$year_ago\")" -c id -c name
```

`modified_timestamp` changes with any edit of the resource, not only of its password.

## 2. Generate the new password

`passbolt generate` follows the password policies of the organization, as the browser extension
does (see [generate](../cli/commands/generate.md)):

```bash
passbolt generate                          # the default generator of the organization
passbolt generate password --length 32     # override one setting, keep the others
passbolt generate passphrase --words 6
```

Some services refuse some characters. Choose the character sets they accept:

```bash
passbolt generate password --length 24 --charset upper,lower,digit
```

## 3. Update Passbolt and the service

Choose which side changes first:

| Order | When | How the password travels |
|---|---|---|
| Passbolt first | Passbolt can generate the password | `update resource --generate`, then `exec` hands it to the service. It is never on a command line. |
| The service first | The service generates or validates the password itself | You hold it in a shell variable and pass it with `--password`. |

### Passbolt first, with `--generate`

`update resource --generate` stores a password generated from the policies. The service then
reads it from Passbolt with [`exec`](exec.md):

```bash
id="<UUID>"

passbolt get resource --id "$id" --json > previous.json   # see below
passbolt update resource --id "$id" --generate --expiry 90d

NEW_PASSWORD="passbolt://$id" passbolt exec -- ./set-service-password.sh
```

`set-service-password.sh` reads `$NEW_PASSWORD` and sets it on the service, for example with
`ALTER ROLE` on PostgreSQL or the API of the service. If it fails, the old password is still in
`previous.json`.

:::caution
`previous.json` holds the old password in clear. Run `umask 077` before writing it, and remove it
once the service accepts the new password.
:::

### The service first

Change the password on the service, then store it:

```bash
new=$(passbolt generate password --length 24 --charset upper,lower,digit)
printf '%s\n' "$new" | ./set-service-password.sh     # reads it on stdin
passbolt update resource --id "$id" --password "$new" --expiry 90d
```

`--password` puts the password on the command line of `passbolt`, where other users of the
machine can see it with `ps` for a moment. Run it on a machine you alone use.

If `update resource` fails, the new password is only in `$new`: print it to stderr, or retry,
before the script ends.

## 4. Set the expiry

`--expiry` takes an absolute date or a delay from now (see
[expiry dates](../cli/filters.md#expiry-dates)):

```bash
passbolt update resource --id "$id" --expiry 90d
passbolt update resource --id "$id" --expiry 2027-03-31T00:00:00Z
passbolt update resource --id "$id" --expiry none        # no expiry
passbolt update resource --id "$id" --expiry=-1h         # mark it expired now
```

`--expiry=-1h` marks a password for rotation, for example after someone who knew it left: it then
shows in the list of step 1.

:::note
A value starting with `-` needs the `=` form: `--expiry -1h` is read as an unknown flag.
:::

Create a resource with an expiry the same way:

```bash
passbolt create resource --name "Registry token" --username ci --generate --expiry 30d
```

## 5. Check the result

```bash
passbolt list resource --filter "id == \"$id\"" -c name -c modified_timestamp -c expired_at
```

The resource keeps its ID, its permissions and its folder: the users and the scripts that read
it get the new password at their next read.

## Next steps

- [Scripting](scripting.md): run the rotation from a script.
- [Injecting secrets](exec.md): let services read the password from Passbolt at each run.
- [generate](../cli/commands/generate.md): every generator option.
