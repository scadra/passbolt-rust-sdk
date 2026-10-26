
	      ____                  __          ____
	     / __ \____  _____ ____/ /_  ____  / / /_
	    / /_/ / __ `/ ___/ ___/ __ \/ __ \/ / __/
	   / ____/ /_/ (__  |__  ) /_/ / /_/ / / /_
	  /_/    \__,_/____/____/_.___/\____/_/\__/

	Open source password manager for teams
	(c) 2025 Passbolt SA
	https://www.passbolt.com

## License

Passbolt - Open source password manager for teams

(c) 2025 Passbolt SA

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General
Public License (AGPL) as published by the Free Software Foundation version 3.

The name "Passbolt" is a registered trademark of Passbolt SA, and Passbolt SA hereby declines to grant a trademark
license to "Passbolt" pursuant to the GNU Affero General Public License version 3 Section 7(e), without a separate
agreement with Passbolt SA.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along with this program. If not,
see [GNU Affero General Public License v3](http://www.gnu.org/licenses/agpl-3.0.html).

## About passbolt

Passbolt is an open source password manager for teams. It allows to securely share and store credentials.
For instance, the wifi password of your office, or the administrator password of a router, or your organisation social
media account password, all of them can be secured using Passbolt.

You can try a demo of passbolt at [https://demo.passbolt.com](https://demo.passbolt.com).

## About passbolt-rs

A fast, secure CLI and SDK for [Passbolt](https://www.passbolt.com/) — written in Rust.

Full alternative to [go-passbolt-cli](https://github.com/passbolt/go-passbolt-cli) with no OpenSSL dependency (pure Rust TLS + GPG).
The workspace also ships the `passbolt-sdk` library and its WASM and FFI bindings.

# Contributing

Please check [CONTRIBUTING.md](CONTRIBUTING.md) for more information about how to get involved.

## Reporting a security Issue

If you've found a security related issue in Passbolt, please don't open an issue on GitHub. Follow our responsible disclosure process: https://www.passbolt.com/docs/contribute/security/vulnerability/.

# Quick how-to

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Authentication](#authentication)
- [Commands](#commands)
  - [configure](#configure)
  - [verify](#verify)
  - [completion](#completion)
  - [resource](#resource)
  - [folder](#folder)
  - [user](#user)
  - [group](#group)
  - [exec](#exec)
  - [export](#export)
  - [migrate-metadata](#migrate-metadata)
- [Global Flags](#global-flags)
- [Output Formats](#output-formats)
- [Filter Syntax](#filter-syntax)
- [Expiry Format](#expiry-format)
- [MFA](#mfa)
- [TLS / mTLS](#tls--mtls)
- [Security Notes](#security-notes)

---

## Installation

```bash
git clone https://github.com/scadra/passbolt-rust.git
cd passbolt-rust
cargo build --release
# binary at target/release/passbolt
sudo cp target/release/passbolt /usr/local/bin/
```

**Requirements:** Rust 1.88+ (no OpenSSL required — uses rustls).

---

## Quick Start

```bash
# 1. Configure credentials
passbolt configure \
  --server-address https://passbolt.example.com \
  --user-private-key-file ~/.gnupg/private.asc \
  --user-password "my-gpg-passphrase"

# 2. Verify server identity (optional but recommended)
passbolt verify

# 3. List all passwords
passbolt list resource

# 4. Get a specific password (decrypted)
passbolt get resource --id <UUID>

# 5. Create a new entry
passbolt create resource --name "GitHub" --username "john" --uri https://github.com
```

---

## Configuration

Config file location: `~/.config/passbolt/config.toml`. When it does not exist, the config
file of go-passbolt-cli is read (and `configure` / `verify` update it, with its keys):
`~/.config/go-passbolt-cli/go-passbolt-cli.{json,toml,yaml,yml}`. `--config` takes a `.toml`,
`.json` or `.yaml` file. Keys are read whatever their case and underscores: go-passbolt-cli's
`serveraddress` or `serverAddress` is `server_address`. Reading or writing a config file
restricts it to its owner (`0600`).

```toml
server_address         = "https://passbolt.example.com"

# PGP private key — `configure --user-private-key-file` saves the content of the file
user_private_key       = """-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----"""

user_password          = "my-gpg-passphrase"

# MFA (optional)
mfa_mode               = "interactive-totp"   # or "noninteractive-totp" / "none"
mfa_totp_token         = ""                   # TOTP secret (for noninteractive)
mfa_totp_offset        = "0s"                 # clock skew, Go duration (e.g. "-30s")
mfa_retrys             = 3
mfa_delay              = "10s"

# TLS
tls_skip_verify        = false
# tls_client_cert        = """-----BEGIN CERTIFICATE----- ..."""   # mTLS, PEM
# tls_client_private_key = """-----BEGIN PRIVATE KEY----- ..."""
# proxy                  = "http://proxy.example.com:3128"
# resolve                = "passbolt.example.com:443:10.0.0.5"     # like curl --resolve

# Written by `passbolt verify`: do not edit by hand
# server_public_key        = """-----BEGIN PGP PUBLIC KEY BLOCK----- ..."""
# metadata_key_fingerprint = "..."
# server_verify_token      = "..."   # go-passbolt-cli's verification, also checked
# server_verify_enc_token  = "..."

# Performance
timeout                = "1m0s"   # each request and the whole command
workers                = 0    # 0 = auto (number of CPU cores)

# Debug
debug                  = false
```

### Priority Order

CLI flags > `PASSBOLT_*` variables > go-passbolt-cli variables (`SERVERADDRESS`,
`USERPASSWORD`, `MFAMODE`…: the flag name in capitals) > Config file > Defaults

Durations use Go's syntax (`30s`, `1m30s`, `500ms`, `-1m`); a plain number is seconds.
Booleans take `--debug`, `--debug=true` or `--debug=false`; in a variable or a file also `1`,
`0`, `t`, `f`. An invalid go-passbolt-cli variable is ignored, as go-passbolt-cli does
(`DEBUG=*` does not stop the CLI); an invalid `PASSBOLT_*` variable is an error.

`passbolt configure` saves every setting in effect (flags, variables, config file, defaults),
except the secrets set by a variable (password, TOTP secret, private keys): a secret exported
for one command never ends up on disk. Give a secret on the command line to save it.

---

## Authentication

The CLI logs in with **GPGAuth**, as the browser extension does, then keeps the session cookie:

1. Once `passbolt verify` pinned the server key, the server first proves it holds its private
   key: it must decrypt a fresh token (`POST /auth/verify.json`).
2. `POST /auth/login.json` with the user's key fingerprint: the server answers a challenge
   encrypted for the user.
3. The CLI decrypts it, checks it is a GPGAuth token, and sends it back.
4. The server sets the session cookie; requests then carry the CSRF token.

Each answer must carry the `X-GPGAuth-*` headers of its step (version 1.3.0, progress,
authenticated flag), as the browser extension checks them: a proxy or another server answering
instead of Passbolt is refused. After login, the CLI checks the server's copy of the user's key
matches the private key.

---

## Commands

### configure

Save the [global flags](#global-flags) given, with the variables and the config file, to the
config file. Silent on success; `--debug` prints what was saved, secrets masked.

```bash
passbolt configure --serverAddress https://passbolt.example.org \
  --userPrivateKeyFile keys/privatekey.asc --userPassword '1234'
```

The private key file is read: its content is saved, not its path. The secrets are saved only
when given as flags, never from the environment (see [Priority Order](#priority-order)).

---

### verify

Pin the server key and the shared metadata key in the config file, with the settings given
(as `configure`), then print `Verification Enabled`. Needs no MFA; the password is asked for
when it is not given.

```bash
passbolt verify
passbolt verify --force   # trust keys that changed, once your administrator confirmed it
```

- go-passbolt-cli's `server_verify_token` / `server_verify_enc_token` are saved too: either CLI
  checks the server with the same config file.
- The shared metadata key is pinned only when the account logs in without MFA.

- The server key is pinned once the server proved it holds the private key; each login then
  checks it again. Its fingerprint is computed from the key, not taken from the server.
- The active shared metadata key is pinned: shared metadata is only encrypted for it.
- A pinned key that changed is refused until `--force`.

---

### completion

Generate shell completion scripts.

```bash
passbolt completion bash   >> ~/.bashrc
passbolt completion zsh    >> ~/.zshrc
passbolt completion fish   > ~/.config/fish/completions/passbolt.fish
passbolt completion powershell
```

---

### resource

#### list resource

```bash
passbolt list resource [OPTIONS]
```

| Option | Description |
|---|---|
| `--favorite` | Only show favorited entries |
| `--own` | Only show entries owned by the current user |
| `-g, --group <UUID>` | Only the resources shared with this group (one) |
| `-f, --folder <UUID>` | Filter by folder (repeatable) |
| `-s, --search <TEXT>` | Part of the name, any case (v5 names decrypted) |
| `-c, --column <COL>` | Columns to display (repeatable): `ID`, `Name`, `Username`, `URI` |
| `--filter <EXPR>` | Field filter expression (repeatable, see [Filter Syntax](#filter-syntax)) |

```bash
# Examples
passbolt list resource
passbolt list resource --own -c Name -c Username -c URI
passbolt list resource --filter "name~=github" --json
passbolt list resource --folder <FOLDER_UUID> --filter "username!=admin"
```

#### get resource

Retrieve a resource with its **decrypted** password.

```bash
passbolt get resource --id <UUID>
passbolt get resource --id <UUID> --json
```

#### get totp

The current TOTP code of a resource, with the seconds it remains valid.

```bash
passbolt get totp --id <UUID>
```

#### get resource-permissions

List who has access to a resource. Columns: `aro`, `aro_foreign_key` (`ARO ID`), `type`
(`Permission Type`), `id`, `modified`.

```bash
passbolt get resource-permissions --id <UUID>
passbolt get resource-permissions --id <UUID> -c "Permission Type" -c "ARO ID"
```

#### create resource

```bash
passbolt create resource --name <NAME> [OPTIONS]
```

| Option | Description |
|---|---|
| `-n, --name <NAME>` | Entry name **(required)** |
| `-t, --type <SLUG>` | Resource type (`v5-default`, `v5-note`, `password-and-description`…); by default from the fields given and the server's default version |
| `-u, --username <USERNAME>` | Username |
| `--uri <URI>` | URL (repeatable for v5 types) |
| `-p, --password <PASSWORD>` | Password (prompted securely when the type needs one) |
| `-d, --description <DESC>` | Description |
| `--note <NOTE>` | Secret note (`v5-note`) |
| `--pin-code <PIN>` | PIN code (`v5-pin-code`, 4 to 12 digits) |
| `--field <KEY=VALUE>` | Any metadata field, the value read as JSON if it is JSON (repeatable) |
| `--secret-field <KEY=VALUE>` | Any secret field, idem; alone, it also chooses the type |
| `--totp-key <BASE32>` | TOTP secret, with `--totp-algo`, `--totp-digits`, `--totp-period` |
| `-f, --folder-parent-id <UUID>` | Parent folder: the resource gets its permissions |
| `--expiry <EXPIRY>` | Expiry date (see [Expiry Format](#expiry-format)) |

```bash
passbolt create resource \
  --name "AWS Console" \
  --username "john@example.com" \
  --uri https://console.aws.amazon.com \
  --folder-parent-id <FOLDER_UUID> \
  --expiry "90d"
```

#### update resource

```bash
passbolt update resource --id <UUID> [OPTIONS]
```

Options: `--name`, `--username`, `--uri`, `--password`, `--description`, `--note`,
`--pin-code`, `--field`, `--secret-field`, `--expiry`, `--totp-*`, `--remove-totp`. Shared
metadata is encrypted again for the shared key, personal metadata for the user while only they
have access.

```bash
passbolt update resource --id <UUID> --password "newpassword" --expiry "30d"
```

#### delete resource

```bash
passbolt delete resource --id <UUID>
```

#### share resource

```bash
passbolt share resource --id <UUID> [OPTIONS]
```

| Option | Description |
|---|---|
| `-t, --type <TYPE>` | Permission: `1`=Read, `7`=Update, `15`=Owner, `-1`=Revoke (default: `1`) |
| `-u, --user <UUID>` | User to share with (repeatable) |
| `-g, --group <UUID>` | Group to share with (repeatable) |

At least one user or group is required. Revoking someone without access fails before anything
changes.

```bash
passbolt share resource --id <UUID> \
  --type 7 \
  --user <USER_UUID> \
  --group <GROUP_UUID>
```

#### move resource

```bash
passbolt move resource --id <UUID> --folder-parent-id <FOLDER_UUID>
# Move to root:
passbolt move resource --id <UUID> --folder-parent-id ""
# Also change the permissions, as the browser extension does (owners only):
passbolt move resource --id <UUID> --folder-parent-id <FOLDER_UUID> --with-folder-permissions
```

With `--with-folder-permissions`, the resource loses the permissions it got from the folder it
leaves and gets the destination's, the higher level winning: no access is lowered.

---

### folder

#### list folder

```bash
passbolt list folder [OPTIONS]
```

Options: `-s/--search`, `-f/--folder` (parent), `-g/--group` (repeatable: folders shared with
any of the groups), `-c/--column`, `--filter`

#### get folder

```bash
passbolt get folder --id <UUID>
```

#### get folder-permissions

```bash
passbolt get folder-permissions --id <UUID>
```

#### create folder

```bash
passbolt create folder --name "DevOps" --folder-parent-id <PARENT_UUID>
```

A folder created in a shared folder gets its permissions.

#### update folder

```bash
passbolt update folder --id <UUID> --name "New Name"
```

#### delete folder

```bash
passbolt delete folder --id <UUID>             # its content moves to the root
passbolt delete folder --id <UUID> --cascade   # its content is deleted too
```

#### share folder

```bash
passbolt share folder --id <UUID> --type 15 --user <UUID>
passbolt share folder --id <UUID> --type 1 --group <UUID> --with-content
```

With `--with-content`, the change made on the folder is copied onto the sub-folders and
resources the user owns, as the browser extension does: a new access only reaches the items
without one, a change or a removal only the items that have it.

#### move folder

```bash
passbolt move folder --id <UUID> --folder-parent-id <TARGET_UUID>
passbolt move folder --id <UUID> --folder-parent-id <TARGET_UUID> --with-folder-permissions
```

---

### user

#### list user

```bash
passbolt list user [OPTIONS]
```

| Option | Description |
|---|---|
| `-g, --group <UUID>` | Filter by group membership |
| `-r, --resource <UUID>` | Filter by resource access |
| `-s, --search <TEXT>` | Search by name or email |
| `--admin` | Only show admins |
| `-c, --column <COL>` | Columns: `ID`, `Username`, `First Name`, `Last Name`, `Role` |

#### get user

```bash
passbolt get user --id <UUID>
```

#### create user

```bash
passbolt create user \
  --username alice@example.com \
  --firstname Alice \
  --lastname Martin \
  --role user       # or "admin"
```

#### update user

```bash
passbolt update user --id <UUID> --lastname "Dupont" --role admin
```

#### delete user

```bash
passbolt delete user --id <UUID> --dry-run                    # what blocks the deletion
passbolt delete user --id <UUID> --transfer-to <USER_UUID>
```

A user who alone owns shared resources or folders, or alone manages groups, is deleted only
once someone takes them over: `--transfer-to` makes a user (or group) who already has access
owner of each item, and manager of each group they belong to.

---

### group

#### list group

```bash
passbolt list group [OPTIONS]
```

| Option | Description |
|---|---|
| `-u, --user <UUID>` | Filter by member user |
| `-m, --manager <UUID>` | Filter by manager |
| `-c, --column <COL>` | Columns: `ID`, `Name`, `Members` |

#### get group

```bash
passbolt get group --id <UUID>
```

#### create group

```bash
passbolt create group \
  --name "DevOps" \
  --manager <MANAGER_UUID> \
  --user <USER_UUID1> \
  --user <USER_UUID2>
```

At least one `--manager` is required.

#### update group

```bash
passbolt update group --id <UUID> \
  --name "New Name" \
  --user <NEW_MEMBER_UUID> \
  --manager <NEW_MANAGER_UUID> \
  --delete <REMOVED_USER_UUID>
```

#### delete group

```bash
passbolt delete group --id <UUID> --dry-run
passbolt delete group --id <UUID> --transfer-to <USER_UUID>
```

As for users: what the group alone owns needs a new owner first.

---

### exec

Execute a command with Passbolt secrets injected as environment variables.

Any environment variable containing a `passbolt://<UUID>` URI is replaced with the decrypted password before the subprocess starts.

```bash
export DB_PASSWORD="passbolt://a1b2c3d4-e5f6-7890-abcd-ef1234567890"

passbolt exec -- psql -U myuser -d mydb
passbolt exec -- mysql -u root -p"$DB_PASSWORD"
passbolt exec -- ansible-playbook site.yml
```

The subprocess inherits all environment variables; Passbolt URIs are resolved transparently.

---

### export

#### export keepass

Export all accessible resources to a KeePass `.kdbx` file (KDBX4 format, AES-256).

```bash
passbolt export keepass --output ~/backup.kdbx
# Master password is prompted interactively if not provided:
passbolt export keepass --output ~/backup.kdbx --password "kdbx-master-password"
```

Folder structure is preserved in KeePass groups. `--folder-id <UUID>` exports one folder and its
sub-folders. A resource that cannot be decrypted is reported and the command fails, so that a
partial backup never looks complete.

---

### migrate-metadata

Upgrade the v4 resources to v5 (administrators): their name, username, URI and description get
encrypted. A resource only one user can read gets metadata personal to that user, when the
settings allow personal keys; the others the shared metadata key.

```bash
passbolt migrate-metadata
passbolt migrate-metadata --shared-only
```

---

## Global Flags

These flags apply to every command and can be set via CLI, env var, or config file. Each flag
also takes go-passbolt-cli's spelling (`--serverAddress`, `--userPrivateKeyFile`,
`--mfaTotpToken`, `--tlsSkipVerify`…), and each setting go-passbolt-cli reads from the
environment is also read from its variable (`SERVERADDRESS`, `USERPRIVATEKEY`, `MFATOTPTOKEN`…).
go-passbolt-cli's deprecated `--totpToken` and `--totpOffset` are taken with a warning.

| Flag | Env Variable | Default | Description |
|---|---|---|---|
| `--server-address` | `PASSBOLT_SERVER_ADDRESS` | — | Server URL |
| `--user-private-key` | `PASSBOLT_USER_PRIVATE_KEY` | — | PGP private key (inline) |
| `--user-private-key-file` | `PASSBOLT_USER_PRIVATE_KEY_FILE` | — | PGP key file, overrides the inline key |
| `--user-password` | `PASSBOLT_USER_PASSWORD` | asked | GPG passphrase |
| `--config` | `PASSBOLT_CONFIG` | `~/.config/passbolt/config.toml` | Config file path |
| `--mfa-mode` | `PASSBOLT_MFA_MODE` | `interactive-totp` | MFA mode |
| `--mfa-totp-token` | `PASSBOLT_MFA_TOTP_TOKEN` | — | TOTP secret |
| `--mfa-totp-offset` | `PASSBOLT_MFA_TOTP_OFFSET` | `0s` | TOTP clock offset (e.g. `-30s`) |
| `--mfa-retrys` | `PASSBOLT_MFA_RETRYS` | `3` | MFA attempts, at most 3 |
| `--mfa-delay` | `PASSBOLT_MFA_DELAY` | `10s` | Minimum delay between MFA attempts |
| `--tls-skip-verify` | `PASSBOLT_TLS_SKIP_VERIFY` | `false` | Skip TLS verification |
| `--tls-client-cert` | `PASSBOLT_TLS_CLIENT_CERT` | — | mTLS client cert (inline) |
| `--tls-client-cert-file` | `PASSBOLT_TLS_CLIENT_CERT_FILE` | — | mTLS client cert file |
| `--tls-client-private-key` | `PASSBOLT_TLS_CLIENT_PRIVATE_KEY` | — | mTLS client key (inline) |
| `--tls-client-private-key-file` | `PASSBOLT_TLS_CLIENT_PRIVATE_KEY_FILE` | — | mTLS client key file |
| `--proxy` | `PASSBOLT_PROXY` | — | HTTP(S) proxy URL |
| `--resolve` | `PASSBOLT_RESOLVE` | — | Pin a host to an address: `host:port:address` |
| `--timeout` | `PASSBOLT_TIMEOUT` | `1m` | Time each request and the whole command may take (`0`: no limit) |
| `--workers` | `PASSBOLT_WORKERS` | `0` (auto) | Parallel workers |
| `--debug` | `PASSBOLT_DEBUG` | `false` | Debug output on stderr: config file, files read, worker count, requests (no secrets) |
| `-j, --json` | — | `false` | JSON output |
| `-v, --version` | — | — | `passbolt version X (Built on DATE from Git SHA SHA)` |

Errors print `Error: <message>` on stderr and exit with code 1, usage errors included. The
session keys found while reading resources are saved before logging out
(`Saved N session keys to server` on stderr).

---

## Output Formats

**Table (default)**

```
+--------------------------------------+--------+--------------+
| ID                                   | Name   | Username     |
+==============================================================+
| a1b2c3d4-e5f6-7890-abcd-ef1234567890 | GitHub | alice        |
| b2c3d4e5-f6a7-8901-bcde-f12345678901 | AWS    | ops@corp.com |
+--------------------------------------+--------+--------------+
```

**JSON** (`--json`)

```bash
passbolt list resource --json | jq '.[].name'
```

```json
[
  {
    "id": "a1b2c3d4-...",
    "name": "GitHub",
    "username": "alice",
    "uri": "https://github.com"
  }
]
```

**Key-Value** (`get` commands without `--json`)

```
ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
Type: v5-default
Name: GitHub
Username: alice
URI: https://github.com
Password: s3cr3t
Description:
Expiry:
```

---

## Filter Syntax

The `--filter` flag supports the following operators:

| Operator | Meaning | Example |
|---|---|---|
| `field=value` | Exact match (case-insensitive) | `--filter "role=admin"` |
| `field~=value` | Contains | `--filter "name~=github"` |
| `field^=value` | Starts with | `--filter "username^=john"` |
| `field$=value` | Ends with | `--filter "uri$=.com"` |
| `field!=value` | Not equal | `--filter "username!=admin"` |

The first operator written splits the expression: `uri=https://a/?x!=y` is `uri` equal to
`https://a/?x!=y`.

Multiple `--filter` flags are ANDed together:

```bash
passbolt list resource \
  --filter "name~=prod" \
  --filter "username!=root"
```

---

## Expiry Format

Used with `create resource` and `update resource`:

| Value | Meaning |
|---|---|
| `"2025-12-31T00:00:00Z"` | Absolute date (RFC3339) |
| `"90d"` | 90 days from now |
| `"48h"` | 48 hours from now |
| `"30m"` | 30 minutes from now |
| `"none"` or `""` | Remove expiry |

```bash
passbolt create resource --name "Temp token" --expiry "7d"
passbolt update resource --id <UUID> --expiry "none"
```

---

## MFA

Three modes are supported:

**`interactive-totp`** (default) — asks for the TOTP code on stderr (`Enter TOTP:`), read
from the terminal or, when stdin is not one, from stdin; 3 attempts, `TOTP Verification Failed`
after a refused code. The password is asked for the same way (`Enter Password:`) when not given.

**`noninteractive-totp`** (also spelt `non-interactive-totp`) — provide the TOTP *secret* (not
the 6-digit code) in config or env:
```bash
passbolt list resource \
  --mfa-mode noninteractive-totp \
  --mfa-totp-token "JBSWY3DPEBLW64TMMQ======"
```
The CLI computes the current code automatically. Use `--mfa-totp-offset` to compensate for clock drift.
A new attempt waits for the next TOTP code: the same code is never sent twice.

The server disables an account after too many wrong codes: the CLI sends at most 3 per session,
whatever `--mfa-retrys` says (go-passbolt-cli sends `--mfaRetrys` + 1), and stops as soon as
the server ends the session. An account
without TOTP (Yubikey, Duo…) gets an error naming the MFA it has.

**`none`** — disable MFA (for accounts without MFA configured). Any other mode is `none`, as for
go-passbolt-cli.

---

## TLS / mTLS

Server certificates are checked against the system's roots (also `SSL_CERT_FILE` /
`SSL_CERT_DIR`) and Mozilla's. HTTPS is required, except for a server on localhost.

Skip verification (self-signed certs, labs):
```bash
passbolt list resource --tls-skip-verify
```

Mutual TLS (client certificate authentication):
```bash
passbolt list resource \
  --tls-client-cert-file /etc/passbolt/client.crt \
  --tls-client-private-key-file /etc/passbolt/client.key
```

Or inline in config:
```toml
tls_client_cert = """-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----"""
tls_client_private_key = """-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----"""
```

---

## Security Notes

- No OpenSSL dependency — TLS via [rustls](https://github.com/rustls/rustls), GPG via [pgp](https://github.com/rpgp/rpgp) (pure Rust).
- The passphrase is kept as a `secrecy::SecretString`, never logged, even in `--debug` mode; the
  config and the KeePass entries are zeroized on drop with [`zeroize`](https://github.com/RustCrypto/utils/tree/master/zeroize).
  Decrypted secrets do pass through ordinary strings on their way to the output.
- With `passbolt verify`, each login checks the server holds the pinned key, and shared metadata
  is only encrypted for the pinned metadata key.
- Nothing is encrypted for a revoked or expired key.
- What the CLI writes is checked against OpenPGP.js, the library of the browser extension
  (`tests/interop`).

---

## Development

```bash
cargo build --release
cargo test
cargo clippy -- -D warnings
cargo fmt
bash scripts/license-headers.sh   # every .rs file must carry the Passbolt license header
```

### Tests

`cargo test` runs everything that needs no server:

| Level | Location | Against |
|---|---|---|
| Unit | `crates/*/src` (`#[cfg(test)]`) | single functions |
| SDK integration | `crates/passbolt-sdk/tests/it` | in-memory fake Passbolt API, data in `tests/fixtures` |
| CLI | `crates/passbolt-cli/tests/cli_test.rs` | the `passbolt` binary, offline |

Known bugs are `#[ignore]`d tests naming their ticket: `cargo test -- --ignored` lists them.

### End-to-end tests

`scripts/e2e.sh` runs the CLI against a real Passbolt server (`crates/passbolt-cli/tests/e2e`).

```bash
cp .env.e2e.example .env.e2e   # then adapt it; .env.e2e is git-ignored
scripts/e2e.sh                  # release build, 4 tests in parallel
E2E_THREADS=1 scripts/e2e.sh created_resource   # one test, sequentially
```

The server needs a user and an admin account without MFA, a second user to share with,
and v4 resource creation allowed. Every test creates uniquely named data and deletes it,
even when it fails.

# Credits

https://www.passbolt.com/credits
