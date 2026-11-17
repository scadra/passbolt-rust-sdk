---
title: Troubleshooting
sidebar_position: 9
---

# Troubleshooting

Find what an error message means and how to fix it, and read the exit codes of the CLI.

## Diagnose an error

An error prints one line on stderr: `Error: `, each step it went through, then the message.

```text
Error: logging in: Configuration error: server_address must use https, not http
```

Add `--debug` (or set `debug = true` in the config file) to see on stderr what the CLI does:

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

It prints:

- The config file read, the key files loaded (`Loading file: <path>`), the number of workers.
- Each request, method and URL without its query (it may hold search terms), then the status
  of its answer.
- With `verify`, the fingerprints of the keys pinned.

Secrets are never printed: no headers, no bodies, no passwords, no keys.

- `configure --debug` prints the settings saved on stdout, the secrets as `********`.
- `exec --debug` prints on stdout which variables it filled
  (`<NAME> env var populated with resource id <id>`), not their values.

Prompts (`Enter Password:`, `Enter TOTP:`), warnings and `Saved <n> session keys to server` go to
stderr. stdout holds the result only: with `--json`, you can pipe it to `jq` as it is. See
[output](output.md).

## Exit codes

| Code | When |
|---|---|
| `0` | Success. Also `--help`, `--version`, and a command with subcommands given nothing (`passbolt`, `passbolt list`): its help is printed on stdout. |
| `1` | Any error, usage errors included (unknown flag, missing argument: clap prints `error: ...` and the usage). |
| The command's | [`exec`](commands/exec.md) exits with the code of the command it ran; `1` when the command was ended by a signal. |

`export keepass` and `export csv` skip the resources they cannot decrypt, print why, and still
exit `0`.

## Settings

### `serverAddress is not defined`

```text
Error: serverAddress is not defined
Error: userPrivateKey is not defined
```

No server address, or no private key, was found: there is no config file, or the setting is
missing from it.

Give the setting with `--server-address` or `--user-private-key-file`, with a variable
(`PASSBOLT_SERVER_ADDRESS`, or the plain `SERVERADDRESS`), or save it with `passbolt configure`.
`--debug` prints the config file read, if any. See [configuration](configuration.md).

### The private key file cannot be read

```text
Error: Cannot read private key file: <path>: No such file or directory (os error 2)
```

The file given with `--user-private-key-file` does not exist, or you cannot read it. Check the
path.

### HTTPS required

```text
Error: logging in: Configuration error: server_address must use https, not http
```

Plain HTTP is refused, except for a server on the machine itself (`localhost`, `127.0.0.1`,
`::1`). Use the `https://` address of the server.

### The server address is not a URL

```text
Error: logging in: Configuration error: invalid server_address: relative URL without a base
```

Give the address with its scheme: `https://passbolt.example.com`.

## Login

### Wrong passphrase, or a key that does not decrypt

```text
Error: logging in: Login failed: Failed to decrypt server challenge: PGP decryption failed: ...
```

The passphrase (`--user-password`, `user_password`) does not unlock the private key, or the key
is not the one of this account on this server. Check both.

When no passphrase is given, the CLI asks for it (`Enter Password:`). When stdin is not a
terminal, it reads the first line of stdin.

### `Post-login key cross-check failed`

```text
Error: logging in: Post-login key cross-check failed
```

The login worked, but the key the server holds for the account does not match the private key
used: the account was set up again with another key. Use the current key.

### The server key changed

At login:

```text
Error: logging in: Server identity mismatch: the server could not prove it holds its private key
```

The server could not decrypt the token encrypted for the key pinned by `passbolt verify`: its
key changed, or another server answers. `passbolt verify` then refuses it:

```text
Error: The server key changed: <pinned> is pinned, the server now has <current>. Check the change with your administrator, then run `passbolt verify --force` to trust the new key.
```

Ask your administrator whether the server key was changed, and compare the fingerprint. Only
then run `passbolt verify --force`.

### The stored server verification is incomplete

```text
Error: logging in: Server identity mismatch: the stored server verification is incomplete: run `passbolt verify` again
```

The verification tokens of the config file were edited or truncated. Run `passbolt verify`.

## Network and TLS

### Server certificate not trusted

```text
Error: logging in: Network error: POST https://passbolt.example.com/auth/login.json: error sending request for url (https://passbolt.example.com/auth/login.json)
```

The same message comes for a server that cannot be reached, and for a certificate the CLI does
not trust (self-signed, or signed by an internal authority). Certificates are checked against
the system's roots and Mozilla's.

- For an internal authority, add it to the system's roots, or point `SSL_CERT_FILE` (or
  `SSL_CERT_DIR`) at it.
- For a lab with a self-signed certificate, use `--tls-skip-verify`. Do not use it in
  production.

See [TLS and proxies](tls.md).

### Client certificate without its key

```text
Error: Configuration error: client TLS private key is empty, but client TLS cert was set
Error: Configuration error: client TLS cert is empty, but client TLS private key was set
```

Mutual TLS needs both the certificate and its private key. Give `--tls-client-cert-file` and
`--tls-client-private-key-file`, or `tls_client_cert` and `tls_client_private_key`.

### Client certificate or key not valid

```text
Error: HTTP error: Failed to parse client TLS identity: ...
```

The certificate or the key is not PEM, or the key does not match the certificate.

### Proxy URL not valid

```text
Error: HTTP error: Failed to configure HTTP proxy: ...
```

The `--proxy` URL is not valid. Give it as `http://proxy.example.com:3128`.

A proxy that cannot be reached, or that refuses the connection, gives the `Network error:` of
[Server certificate not trusted](#server-certificate-not-trusted).

### Another server answers in place of Passbolt

```text
Error: logging in: Login failed: GPGAuth: ...
```

A proxy or another server answered in place of Passbolt: its answers lack the `X-GPGAuth-*`
headers. Check the server address and the proxy. See [authentication](authentication.md#gpgauth).

### Timeouts

```text
Error: context deadline exceeded (--timeout 1m0s)
```

`--timeout` (default `1m`) bounds each request and the whole command. A large vault, a slow
server or a slow link can need more: use `--timeout 5m`, or `--timeout 0` for no limit.

`exec` and `tui` are not bounded: they run as long as needed.

## MFA

### TOTP code refused 3 times

In interactive mode (`interactive-totp`, the default):

```text
Enter TOTP:
TOTP Verification Failed
Error: logging in: failed MFA Challenge 3 times: <message of the server>
```

The code was refused 3 times. Check the clock of the phone that gives the codes, and that the
code is the one of this account.

### Computed TOTP codes refused

In non-interactive mode (`noninteractive-totp`):

```text
Error: logging in: MFA verification failed after 3 attempt(s): <message of the server>
```

The codes the CLI computed were refused.

- Check that `mfa_totp_token` is the TOTP *secret* of the account, not a 6-digit code.
- Check the clock of the machine. Compensate a clock that drifts with `--mfa-totp-offset`
  (e.g. `-30s`, `1m`).

### TOTP secret is not base32

```text
Error: Invalid argument: Invalid TOTP secret (must be base32): ...
```

The TOTP secret given with `--mfa-totp-token` or `mfa_totp_token` is not base32. Give
the secret in base32, as authenticator apps take it.

### The server ended the session after too many attempts

```text
Error: logging in: The server ended the session after too many MFA attempts: <message of the server>
```

The server stopped the attempts, and may disable the account after more wrong codes. The CLI
sends at most 3 codes per session.

Wait, check the secret and the clock, then try again. An administrator re-enables a disabled
account.

### The account's MFA is not TOTP

```text
Error: logging in: MFA with a TOTP code is not enabled for this account; it offers: yubikey, duo
```

The account has MFA, but not TOTP, and the CLI answers TOTP only. Add TOTP to the account, or use
an account without MFA.

### `MFA required`

```text
Error: logging in: MFA required
```

The account has MFA, and `mfa_mode` is `none` (or a mode not known). Set
`--mfa-mode interactive-totp` or `noninteractive-totp`. See
[authentication](authentication.md#mfa).

## Shared metadata key

### The shared metadata key changed

When you create or update a resource, and the shared metadata key of the server is not the one
pinned:

```text
Error: creating resource: The shared metadata key changed: <pinned> was trusted, the server now uses <active>. Check the new key with your administrator, then run `passbolt verify` to trust it.
```

The CLI does not encrypt metadata for a key it does not trust.

1. Check the new key with your administrator.
2. Run `passbolt verify`. It answers
   ``The metadata key changed: ... run `passbolt verify --force` to trust the new key.``
3. Run `passbolt verify --force`.

The metadata key is pinned only by an account that logs in without MFA. See
[authentication](authentication.md#pinning-the-server-verify).

### The shared metadata key is not shared with you

```text
Error: creating resource: PGP encryption failed: the shared metadata key is not shared with you yet: ask an administrator to share it
```

The organization encrypts metadata with a shared key, which exists but was not shared with this
account yet. An administrator shares it from the browser extension.

### The server has no shared metadata key

```text
Error: creating resource: PGP encryption failed: the server has no active shared metadata key
```

The organization encrypts metadata with a shared key, but no shared key is active on the server.
An administrator creates one.

## Resources and permissions

### Permission denied, or not found

```text
Error: getting resource: API error (404): <message of the server>
Error: deleting Resource <id>: API error (403): DELETE /resources/<id>.json failed: <message of the server>
```

`API error (<status>)` is the answer of the server, with its message:

| Status | Usual cause |
|---|---|
| `400` | A value the server refused (the message names it). |
| `403` | The account lacks the permission: read only, not owner, not administrator. |
| `404` | Wrong ID, or the item is not shared with the account: the server answers the same in both cases. |

Check the ID with `list`, and who has access with `get resource permission --id <id>` (see
[resources](commands/resources.md#get-resource-permission)).

### An ID is not a UUID

```text
Error: Invalid argument: "abc" is not a UUID
```

An ID that is not a UUID is refused before any request. Copy the ID from `list`.

### A resource is skipped

```text
Warning: resource <id> skipped: <reason>
```

`list resource` could not decrypt this resource (its secret or its metadata), and lists the
others. The exports print the same as
`Skipping Export of Resource <id> <name> Because of: <reason>`. `get resource` on such a resource
fails with the same reason.

The reason names what failed:

- `PGP decryption failed: resource <id> secret: ...` or `resource <id> metadata: ...`: it was not
  encrypted for this account's key (shared before a key change, or by a client that failed). The
  owner shares it again.
- `PGP decryption failed: metadata key <id> share: ...`: the shared metadata key given to the
  account cannot be decrypted.

### `required flag "password" not set`

```text
Error: required flag "password" not set
```

`create resource` without `--password` asks for the password in a terminal only. In a script,
give `--password`, or `--generate`.

### The password generator refuses a length

```text
Error: Invalid argument: the password length must be between 8 and 128, not 2
Error: Invalid argument: a passphrase must have between 4 and 40 words, not 1
Error: a PIN code has 4 to 12 digits, not 2
```

The bounds are those of the password policies of the organization, or of the defaults of
Passbolt with `--offline`. Choose a value within them. See [generate](commands/generate.md).

### The password policies cannot be read

```text
Error: reading the password policies: API error (403): ...
```

The policies could not be read from the server. Use `generate --offline`. See
[generate](commands/generate.md).

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

## KeePass export

### Give the KeePass password from a script

Without `--password` nor `--keyfile`, `export keepass` asks `Enter KeePass Password:`. When
stdin is not a terminal, it reads the first line of stdin instead, without prompting further:

```bash
printf '%s\n' "$KDBX_PASSWORD" | passbolt export keepass -f vault.kdbx
```

See [export keepass](commands/export-keepass.md).

### `EOF`

```text
Error: EOF
```

The CLI read the KeePass password from stdin, and stdin was empty or closed. Pipe the password
in, or give `--password` or `--keyfile`.

### A KDBX 4 file needs a password

```text
Error: A KDBX 4 file needs a password or a key file
```

The answer was empty with `--kdbx-version v4`. Give a password or a key file. A KDBX 3 file is
written without password when the answer is empty.

## Terminal UI

### Clipboard in the terminal UI

Over SSH, or on a machine without a clipboard, `passbolt tui` copies through the terminal
(OSC 52). A terminal that ignores it copies nothing, without an error.

Use a terminal that accepts it, set `set -g set-clipboard on` in tmux, or show the password with
`s`. See [terminal UI](tui.md#clipboard).

## Get help

- Bugs and questions on this CLI: the
  [issue tracker](https://github.com/scadra/passbolt-rust-sdk/issues). Give the version
  (`passbolt --version`), the command, and the output of `--debug`.
- Questions on Passbolt itself: the [community forum](https://community.passbolt.com).
- Security issues: do not open an issue; follow the disclosure process in
  [security](../security.md#reporting-a-vulnerability).

## Related

- [Configuration](configuration.md): every setting.
- [Authentication](authentication.md): `verify` and MFA.
- [TLS and proxies](tls.md): certificates and proxies.
