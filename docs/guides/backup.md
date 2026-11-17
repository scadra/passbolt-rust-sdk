---
title: Backups
sidebar_position: 6
---

# Backups

Export your vault on a schedule to a KeePass file that opens without the Passbolt server, and
restore it with `passbolt import`.

`passbolt export keepass` writes the resources an account can read to an encrypted KeePass file.
`passbolt export csv` writes them in clear, for another password manager.

:::note
An export holds what the account can read, decrypted: not the permissions, the groups, the users
or the history. It does not replace a backup of the server (its database and its keys), which
the administrator makes.
:::

## Prerequisites

- A dedicated Passbolt account with read access to what must be backed up, as for
  [CI pipelines](ci.md#1-create-a-dedicated-account).
- A system user `backup` on the machine that runs the backups.

## 1. Configure the account

Give the account a config file of its own:

```bash
sudo -u backup passbolt --config /etc/passbolt-backup/config.toml configure \
  --server-address https://passbolt.example.com \
  --user-private-key-file /etc/passbolt-backup/private.asc
sudo -u backup passbolt --config /etc/passbolt-backup/config.toml verify
```

- `configure` saves the content of the key file, readable by its owner only (`0600`). You can
  then remove the key file itself.
- The passphrase stays out of the file: it comes from a variable at each run (see step 3).
- An account with TOTP also needs `PASSBOLT_MFA_MODE=noninteractive-totp` and
  `PASSBOLT_MFA_TOTP_TOKEN` (see [MFA](../cli/authentication.md#mfa)).

## 2. Choose how to lock the KeePass file

| Lock | Flags | Asked for at each run |
|---|---|---|
| A key file | `--keyfile` | Nothing. |
| A password | `-p`, or a prompt read from stdin | The password. |
| Both | `-p` with `--keyfile` | Nothing. |

### A key file

Nothing is asked for:

```bash
passbolt export keepass -f vault.kdbx --keyfile /etc/passbolt-backup/backup.key
```

Any file can be a key file. Create one with `head -c 64 /dev/urandom > backup.key`, or with
KeePassXC.

:::caution
Keep the key file away from the backups, on another machine or medium: whoever holds both opens
the backup.
:::

### A password

`-p` takes the password, but puts it on the command line, where `ps` shows it. Without `-p` and
without `--keyfile`, the CLI asks `Enter KeePass Password:`, and reads the answer from stdin when
stdin is not a terminal. Pipe it from a variable:

```bash
printf '%s\n' "$KDBX_PASSWORD" | passbolt export keepass -f vault.kdbx
```

- An empty answer writes a file without a password: make sure the variable is set
  (`${KDBX_PASSWORD:?}`).
- For this to work, the passphrase of the account must come from `PASSBOLT_USER_PASSWORD`, and
  the MFA must not be interactive: otherwise their prompts read stdin first.

### Both

Give `-p` with `--keyfile`. With `--keyfile` and without `-p`, nothing is asked for and the file
is locked by the key file alone: the stdin answer above only applies without a key file.

### Other options

- `--kdbx-version v4` writes KDBX 4 (Argon2) instead of KDBX 3.1.
- `--folder-id <UUID>` exports one folder and its sub-folders only.

See [export keepass](../cli/commands/export-keepass.md).

## 3. Write the backup script

```bash title="/usr/local/bin/passbolt-backup"
#!/usr/bin/env bash
set -euo pipefail
umask 077

: "${PASSBOLT_USER_PASSWORD:?}"

dir=/var/backups/passbolt
file="$dir/passbolt-$(date -u +%Y%m%d).kdbx"
mkdir -p "$dir"

passbolt --config /etc/passbolt-backup/config.toml --timeout 10m \
  export keepass -f "$file" --kdbx-version v4 --keyfile /etc/passbolt-backup/backup.key

# Keep 30 days.
find "$dir" -name 'passbolt-*.kdbx' -mtime +30 -delete
```

- The CLI writes the export to a temporary file next to the target, readable by its owner only,
  then renames it: a failed run never leaves a half-written file or damages the previous one.
- `umask 077` keeps the directory private too.
- `--timeout` bounds the whole command; a large vault needs more than the default `1m`.
- A resource that cannot be decrypted is reported (`Skipping Export of Resource …`) and left out;
  the export still succeeds. Read the log.
- To export one folder only, add `--folder-id <UUID>`.
- To lock the file with a password instead of the key file, replace the `passbolt` line with
  `printf '%s\n' "${KDBX_PASSWORD:?}" | passbolt … export keepass -f "$file" --kdbx-version v4`,
  and add `KDBX_PASSWORD` to the environment file below.

Put the passphrase of the account in an environment file, mode `0600`:

```bash title="/etc/passbolt-backup/env"
PASSBOLT_USER_PASSWORD=...
```

## 4. Schedule it

Use cron or a systemd timer.

### With cron

```text title="/etc/cron.d/passbolt-backup"
SHELL=/bin/bash
15 2 * * * backup set -a; . /etc/passbolt-backup/env; set +a; /usr/local/bin/passbolt-backup >> /var/log/passbolt-backup.log 2>&1
```

`set -a` exports the variables read from the file, so they are not on the command line. cron runs
the line as `backup`: the environment file must be owned by that user.

### With a systemd timer

```ini title="/etc/systemd/system/passbolt-backup.service"
[Unit]
Description=Passbolt backup
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
User=backup
EnvironmentFile=/etc/passbolt-backup/env
ExecStart=/usr/local/bin/passbolt-backup
UMask=0077
PrivateTmp=true
NoNewPrivileges=true
```

```ini title="/etc/systemd/system/passbolt-backup.timer"
[Unit]
Description=Daily Passbolt backup

[Timer]
OnCalendar=*-*-* 02:15:00
RandomizedDelaySec=15m
Persistent=true

[Install]
WantedBy=timers.target
```

Enable the timer:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now passbolt-backup.timer
sudo systemctl start passbolt-backup.service      # run once now
journalctl -u passbolt-backup.service             # its output
```

systemd reads `EnvironmentFile` as root, before switching to `User=`: the file can stay owned by
root, mode `0600`.

## 5. Check a backup

Open it with KeePassXC, or check it from the command line:

```bash
keepassxc-cli ls -R -k /etc/passbolt-backup/backup.key /var/backups/passbolt/passbolt-20261110.kdbx
```

The database and its top group are named `passbolt export`, with one sub-group per Passbolt
folder.

## Export to CSV

A CSV export is not encrypted. Write it only where it is encrypted otherwise, and keep it as
little as possible:

```bash
umask 077
passbolt export csv --format csv-kdbx -f /secure/passbolt.csv
gpg --encrypt --recipient backup@example.com /secure/passbolt.csv
shred -u /secure/passbolt.csv
```

`csv-kdbx` keeps the folder path in the `Group` column, and the TOTP. The other formats are in
[export csv](../cli/commands/export-csv.md).

## Restore a backup

Restoring is an [import](migration.md): `passbolt import` reads a KDBX file, opened with its
password, its key file, or both.

```bash
passbolt import -f /var/backups/passbolt/passbolt-20261110.kdbx --keyfile /etc/passbolt-backup/backup.key
passbolt import -f vault.kdbx -p "$KDBX_PASSWORD"    # a file locked by a password
```

The `-p` of `import` has no prompt: it takes the password on the command line.

The resources are created again, as new resources, in a new folder `import-<date>`, personal to
the account that imports them. Their old IDs, permissions and history are not restored:

- Share them again. See [sharing](sharing.md).
- Update the `passbolt://<UUID>` references of your scripts to the new IDs.

## Next steps

- [export keepass](../cli/commands/export-keepass.md) and
  [export csv](../cli/commands/export-csv.md): every export option.
- [Migration](migration.md): what `passbolt import` does with a file.
- [Sharing](sharing.md): share the restored resources again.
