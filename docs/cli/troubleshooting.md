---
title: Troubleshooting
sidebar_position: 9
---

# Troubleshooting

## Diagnosing

An error prints one line on stderr, `Error: ` then the message, each step it went through
first: `Error: logging in: Configuration error: server_address must use https, not http`.

`--debug` (or `debug = true` in the config file) prints on stderr what the CLI does:

```bash
passbolt list resource --debug
```

```text
Using config file: /home/ada/.config/passbolt/config.toml
Autodetected Worker Count: 8
[debug] POST https://passbolt.example.com/auth/login.json
[debug] POST https://passbolt.example.com/auth/login.json -> 200
...
```

- The config file read, the key files loaded (`Loading file: <path>`), the number of workers.
- Each request, method and URL without its query (it may hold search terms), then the status
  of its answer.
- With `verify`, the fingerprints of the keys pinned.

Secrets are never printed: no headers, no bodies, no passwords, no keys. `configure --debug`
prints the settings saved on stdout, the secrets as `********`. `exec --debug` prints on stdout
which variables it filled (`<NAME> env var populated with resource id <id>`), not their values.

Prompts (`Enter Password:`, `Enter TOTP:`), warnings and `Saved <n> session keys to server`
go to stderr. stdout holds the result only: with `--json`, it can be piped to `jq` as it is. See
[output](output.md).

## Exit codes

| Code | When |
|---|---|
| `0` | Success. Also `--help`, `--version`, and a command with subcommands given nothing (`passbolt`, `passbolt list`): its help is printed on stdout |
| `1` | Any error, usage errors included (unknown flag, missing argument: clap prints `error: ...` and the usage) |
| the command's | [`exec`](commands/exec.md) exits with the code of the command it ran; `1` when the command was ended by a signal |

`export keepass` and `export csv` skip the resources they cannot decrypt, print why, and still
exit `0`.

## Common problems

### `serverAddress is not defined`

```text
Error: serverAddress is not defined
Error: userPrivateKey is not defined
```

No server address, or no private key, was found: no config file, or the setting is missing in
it. Give it with `--server-address` / `--user-private-key-file`, a variable
(`PASSBOLT_SERVER_ADDRESS`, or the plain `SERVERADDRESS`), or save it with `passbolt configure`.
See [configuration](configuration.md). `--debug` prints the config file read, if any.

A key file that cannot be read:

```text
Error: Cannot read private key file: <path>: No such file or directory (os error 2)
```

### Wrong passphrase, or a key that does not decrypt

```text
Error: logging in: Login failed: Failed to decrypt server challenge: PGP decryption failed: ...
```

The passphrase (`--user-password`, `user_password`) does not unlock the private key, or the key
is not the one of this account on this server. Check both. When no passphrase is given, it is
asked for (`Enter Password:`); with stdin not a terminal, its first line is read.

```text
Error: logging in: Post-login key cross-check failed
```

The login worked, but the key the server holds for the account does not match the private key
used: the account was set up again with another key. Use the current key.

### Server certificate not trusted

```text
Error: logging in: Network error: POST https://passbolt.example.com/auth/login.json: error sending request for url (https://passbolt.example.com/auth/login.json)
```

The same message comes for a server that cannot be reached, and for a certificate the CLI does
not trust (self-signed, or signed by an internal authority). Certificates are checked against
the system's roots and Mozilla's.

- An internal authority: add it to the system's roots, or point `SSL_CERT_FILE` (or
  `SSL_CERT_DIR`) at it.
- A lab with a self-signed certificate: `--tls-skip-verify`. Do not use it in production.

See [TLS and proxies](tls.md).

### HTTPS required

```text
Error: logging in: Configuration error: server_address must use https, not http
```

Plain HTTP is refused, except for a server on the machine itself (`localhost`, `127.0.0.1`,
`::1`). Use the `https://` address of the server.

```text
Error: logging in: Configuration error: invalid server_address: relative URL without a base
```

The address is not a URL: give it with its scheme, `https://passbolt.example.com`.

### Client certificate without its key

```text
Error: Configuration error: client TLS private key is empty, but client TLS cert was set
Error: Configuration error: client TLS cert is empty, but client TLS private key was set
```

Mutual TLS needs both the certificate and its private key: `--tls-client-cert-file` and
`--tls-client-private-key-file`, or `tls_client_cert` and `tls_client_private_key`.

```text
Error: HTTP error: Failed to parse client TLS identity: ...
```

The certificate or the key is not PEM, or the key does not match the certificate.

### Proxy

```text
Error: HTTP error: Failed to configure HTTP proxy: ...
```

The `--proxy` URL is not valid: give it as `http://proxy.example.com:3128`. A proxy that cannot
be reached, or that refuses the connection, gives the `Network error:` above.

A proxy or another server answering in place of Passbolt is refused at login, with a
`Login failed: GPGAuth: ...` message: its answers lack the `X-GPGAuth-*` headers. See
[authentication](authentication.md#gpgauth).

### Timeouts

```text
Error: context deadline exceeded (--timeout 1m)
```

`--timeout` (default `1m`) bounds each request and the whole command. A large vault, a slow
server or a slow link can need more: `--timeout 5m`, or `--timeout 0` for no limit. `exec` and
`tui` are not bounded: they run as long as needed.

### MFA

Interactive mode (`interactive-totp`, the default):

```text
Enter TOTP:
TOTP Verification Failed
Error: logging in: failed MFA Challenge 3 times: <message of the server>
```

The code was refused 3 times. Check the clock of the phone that gives the codes, and that the
code is the one of this account.

Non-interactive mode (`noninteractive-totp`):

```text
Error: logging in: MFA verification failed after 3 attempt(s): <message of the server>
Error: Invalid argument: Invalid TOTP secret (must be base32): ...
```

The first one: the codes computed were refused. Check `mfa_totp_token` is the TOTP *secret* of
the account (not a 6-digit code), and the clock of the machine. A clock that drifts is
compensated with `--mfa-totp-offset` (e.g. `-30s`, `1m`). The second one: the secret is not
base32.

```text
Error: logging in: The server ended the session after too many MFA attempts: <message of the server>
```

The server stopped the attempts, and may disable the account after more wrong codes. The CLI
sends at most 3 codes per session. Wait, check the secret and the clock, then try again; an
administrator re-enables a disabled account.

```text
Error: logging in: MFA with a TOTP code is not enabled for this account; it offers: yubikey, duo
```

The account has MFA, but not TOTP. The CLI answers TOTP only: add TOTP to the account, or use
an account without MFA.

```text
Error: logging in: MFA required
```

The account has MFA, and `mfa_mode` is `none` (or a mode not known). Set
`--mfa-mode interactive-totp` or `noninteractive-totp`. See
[authentication](authentication.md#mfa).

### The server key changed

At login:

```text
Error: logging in: Server identity mismatch: the server could not prove it holds its private key
```

The server could not decrypt the token encrypted for the key pinned by `passbolt verify`: its
key changed, or another server answers. Then `passbolt verify` refuses it:

```text
Error: The server key changed: <pinned> is pinned, the server now has <current>. Check the change with your administrator, then run `passbolt verify --force` to trust the new key.
```

Ask your administrator whether the server key was changed, and compare the fingerprint. Only
then run `passbolt verify --force`.

```text
Error: logging in: Server identity mismatch: the stored server verification is incomplete: run `passbolt verify` again
```

The verification tokens of the config file were edited or truncated: run `passbolt verify`.

### The shared metadata key changed

Creating or updating a resource, when the shared metadata key of the server is not the one
pinned:

```text
Error: creating resource: The shared metadata key changed: <pinned> was trusted, the server now uses <active>. Check the new key with your administrator, then run `passbolt verify` to trust it.
```

The CLI does not encrypt metadata for a key it does not trust. Check the new key with your
administrator. `passbolt verify` then answers
`The metadata key changed: ... run \`passbolt verify --force\` to trust the new key.`: run
`passbolt verify --force`. The metadata key is pinned only by an account that logs in without
MFA; see [authentication](authentication.md#pinning-the-server-verify).

### Shared metadata key missing

```text
Error: creating resource: PGP encryption failed: the shared metadata key is not shared with you yet: ask an administrator to share it
Error: creating resource: PGP encryption failed: the server has no active shared metadata key
```

The organization encrypts metadata with a shared key. The first one: the key exists but was not
shared with this account yet; an administrator shares it from the browser extension. The
second one: no shared key is active on the server; an administrator creates one.

### Permission denied, not found

```text
Error: getting resource: API error (404): <message of the server>
Error: deleting Resource <id>: API error (403): DELETE /resources/<id>.json failed: <message of the server>
```

`API error (<status>)` is the answer of the server, with its message:

| Status | Usual cause |
|---|---|
| `400` | A value the server refused (the message names it) |
| `403` | The account lacks the permission: read only, not owner, not administrator |
| `404` | Wrong ID, or the item is not shared with the account: the server answers the same in both cases |

Check the ID with `list`, and who has access with `get resource permission --id <id>` (see
[resources](commands/resources.md#get-resource-permission)). An ID that is not a UUID is
refused before any request: `Invalid argument: "abc" is not a UUID`.

### A resource skipped

```text
Warning: resource <id> skipped: <reason>
```

`list resource` could not decrypt this resource (its secret or its metadata), and lists the
others. The exports print the same as
`Skipping Export of Resource <id> <name> Because of: <reason>`. The reason names what failed:

- `PGP decryption failed: resource <id> secret: ...` or `resource <id> metadata: ...`: it was not
  encrypted for this account's key (shared before a key change, or by a client that failed);
  the owner shares it again.
- `PGP decryption failed: metadata key <id> share: ...`: the shared metadata key given to the
  account cannot be decrypted.

`get resource` on such a resource fails with the same reason.

### Password generator

```text
Error: Invalid argument: the password length must be between 8 and 128, not 2
Error: Invalid argument: a passphrase must have between 4 and 40 words, not 1
Error: a PIN code has 4 to 12 digits, not 2
Error: reading the password policies: API error (403): ...
```

The bounds are those of the password policies of the organization (or of the defaults of
Passbolt with `--offline`). The last one: the policies could not be read from the server; use
`generate --offline`. See [generate](commands/generate.md).

```text
Error: required flag "password" not set
```

`create resource` without `--password` asks for it in a terminal only; a script must give
`--password`, or `--generate`.

### Deleting a user or a group is refused

```text
Error: The user alone owns 3 resources and 1 folders and alone manages 0 groups: give them to someone with --transfer-to <user or group id> (list them with --dry-run)
```

The user (or group) is the only owner of resources or folders, or the only manager of groups:
deleting it would leave them without an owner. `--dry-run` lists them; `--transfer-to` gives
them to a user or a group who already has access to them:

```bash
passbolt delete user --id <id> --dry-run
passbolt delete user --id <id> --transfer-to <user id>
```

See [users](commands/users.md#delete-user) and [groups](commands/groups.md#delete-group).

### KeePass export password

Without `--password` nor `--keyfile`, `export keepass` asks `Enter KeePass Password:`. When
stdin is not a terminal, it reads the first line of stdin instead, without prompting further:

```bash
printf '%s\n' "$KDBX_PASSWORD" | passbolt export keepass -f vault.kdbx
```

```text
Error: EOF
Error: A KDBX 4 file needs a password or a key file
```

The first one: stdin was empty or closed. The second one: the answer was empty with
`--kdbx-version v4`; a KDBX 3 file is then written without password. See
[export keepass](commands/export-keepass.md).

### Clipboard in the terminal UI

Over SSH, or on a machine without a clipboard, `passbolt tui` copies through the terminal
(OSC 52). A terminal that ignores it copies nothing, without an error. Use a terminal that
accepts it, `set -g set-clipboard on` in tmux, or show the password with `s`. See
[terminal UI](tui.md#clipboard).

## Getting help

- Bugs and questions on this CLI: the
  [issue tracker](https://github.com/scadra/passbolt-rust-sdk/issues). Give the version
  (`passbolt --version`), the command, and the output of `--debug`.
- Questions on Passbolt itself: the [community forum](https://community.passbolt.com).
- Security issues: do not open an issue; follow the disclosure process in
  [security](../security.md#reporting-a-vulnerability).
