---
title: Configuration
sidebar_position: 2
---

# Configuration

Set the server, your key, MFA, TLS and the other settings of the CLI with a config file,
environment variables or flags.

## Config file

The CLI reads `config.toml` in its config directory:

| System | File |
|---|---|
| Linux | `~/.config/passbolt/config.toml` |
| macOS | `~/Library/Application Support/passbolt/config.toml` |
| Windows | `%APPDATA%\passbolt\config\config.toml` |

Point `--config` (or `PASSBOLT_CONFIG`) at another file: a
`.toml`, `.json`, `.yaml` or `.yml` file, its extension giving the format.

- Keys are read whatever their case and underscores: `serveraddress` or `serverAddress` is
  `server_address`.
- Reading or writing a config file restricts it to its owner (`0600`).

```toml title="~/.config/passbolt/config.toml"
server_address         = "https://passbolt.example.com"

# PGP private key: `configure --user-private-key-file` saves the content of the file
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
# server_verify_token      = "..."   # verification token, also checked
# server_verify_enc_token  = "..."

# Performance
timeout                = "1m0s"   # each request and the whole command
workers                = 0        # 0 = auto (number of CPU cores)

# Debug
debug                  = false
```

:::caution
The file holds your private key and, when you save it, your passphrase. Keep it on a machine
only you use.
:::

## Priority order

When a setting is given in several places, the first one found wins:

1. Command-line flags.
2. `PASSBOLT_*` variables, such as `PASSBOLT_SERVER_ADDRESS`.
3. Plain variables: the flag name in capitals, without dashes (`SERVERADDRESS`, `USERPASSWORD`,
   `MFAMODE`…).
4. The config file.
5. The defaults.

An empty variable counts as unset.

## Value formats

- **Durations** use Go's syntax: `30s`, `1m30s`, `500ms`, `-1m`. A plain number is seconds.
  Only `--mfa-totp-offset` takes a negative duration.
- **Booleans** take `--debug`, `--debug=true` or `--debug=false`. In a variable or a file, `1`,
  `0`, `t` and `f` work too.
- **Invalid values**: an invalid plain variable is ignored (`DEBUG=*` does not stop the CLI);
  an invalid `PASSBOLT_*` variable, flag or config file value is an error.

## Saving settings: `configure`

Save every setting in effect (flags, variables, config file, defaults) to the config file.

```bash
passbolt configure [GLOBAL FLAGS]
```

`configure` prints nothing. With `--debug`, it prints what it saved on stdout, secrets masked as
`********`.

It writes to the `--config` file, else to the config file it read, else to
`~/.config/passbolt/config.toml`, in the format of the file's extension.

- The private key file is read: its content is saved, not its path.
- The secrets set by a variable (password, TOTP secret, private keys) are never saved, so a
  secret exported for one command never ends up on disk. Give a secret as a flag to save it.

### Examples

#### Save the server, the key and the passphrase

```bash
passbolt configure --serverAddress https://passbolt.example.com \
  --userPrivateKeyFile keys/privatekey.asc --userPassword '1234'
```

#### Save the settings and print them, secrets masked

```bash
passbolt configure --debug
```

## Global flags

These flags work with every command. Each one can also be set by its variable, or in the config
file under its name with underscores (`--mfa-totp-offset` is `mfa_totp_offset`).

| Flag | Variable | Description |
|---|---|---|
| `--server-address <URL>` | `PASSBOLT_SERVER_ADDRESS` | Server URL. |
| `--user-private-key <KEY>` | `PASSBOLT_USER_PRIVATE_KEY` | PGP private key, armored, inline. |
| `--user-private-key-file <PATH>` | `PASSBOLT_USER_PRIVATE_KEY_FILE` | File of the PGP private key. Overrides the inline key. |
| `--user-password <PASSPHRASE>` | `PASSBOLT_USER_PASSWORD` | Passphrase of the private key. Asked for when not given. |
| `--config <PATH>` | `PASSBOLT_CONFIG` | Config file. Default: `~/.config/passbolt/config.toml`. |
| `--mfa-mode <MODE>` | `PASSBOLT_MFA_MODE` | `interactive-totp`, `noninteractive-totp` or `none`. See [MFA](authentication.md#mfa). Default: `interactive-totp`. |
| `--mfa-totp-token <SECRET>` | `PASSBOLT_MFA_TOTP_TOKEN` | TOTP secret, for `noninteractive-totp`. |
| `--mfa-totp-offset <DURATION>` | `PASSBOLT_MFA_TOTP_OFFSET` | TOTP clock offset, such as `-30s`. Default: `0s`. |
| `--mfa-retrys <N>` | `PASSBOLT_MFA_RETRYS` | MFA attempts, at most 3. Default: `3`. |
| `--mfa-delay <DURATION>` | `PASSBOLT_MFA_DELAY` | Minimum delay between MFA attempts. Default: `10s`. |
| `--tls-skip-verify` | `PASSBOLT_TLS_SKIP_VERIFY` | Skip TLS verification. Default: `false`. |
| `--tls-client-cert <PEM>` | `PASSBOLT_TLS_CLIENT_CERT` | mTLS client certificate, inline. |
| `--tls-client-cert-file <PATH>` | `PASSBOLT_TLS_CLIENT_CERT_FILE` | mTLS client certificate file. |
| `--tls-client-private-key <PEM>` | `PASSBOLT_TLS_CLIENT_PRIVATE_KEY` | mTLS client key, inline. |
| `--tls-client-private-key-file <PATH>` | `PASSBOLT_TLS_CLIENT_PRIVATE_KEY_FILE` | mTLS client key file. |
| `--proxy <URL>` | `PASSBOLT_PROXY` | HTTP(S) proxy URL. |
| `--resolve <HOST:PORT:ADDRESS>` | `PASSBOLT_RESOLVE` | Pin a host to an address, like `curl --resolve`. |
| `--timeout <DURATION>` | `PASSBOLT_TIMEOUT` | Time each request and the whole command may take; `0` for no limit. Raise it to export a large vault. Default: `1m`. |
| `--workers <N>` | `PASSBOLT_WORKERS` | Parallel workers; `0` for the number of CPU cores. Default: `0`. |
| `--debug` | `PASSBOLT_DEBUG` | Debug output on stderr: config file, files read, worker count, requests (no secrets). Default: `false`. |
| `-j, --json` | — | JSON output. Default: `false`. |
| `-v, --version` | — | Print `passbolt version X (Built on DATE from Git SHA SHA)`. `-V` works too. |

### Other spellings

- Each flag also takes a camelCase spelling: `--serverAddress`, `--userPrivateKeyFile`,
  `--mfaTotpToken`, `--tlsSkipVerify`…
- Each setting is also read from its plain variable: `SERVERADDRESS`, `USERPRIVATEKEY`,
  `MFATOTPTOKEN`… The file flags (`--user-private-key-file`, `--tls-client-cert-file`,
  `--tls-client-private-key-file`), `--proxy` and `--resolve` have none.
- The deprecated `--totpToken` and `--totpOffset` still work, with a warning:
  `Flag --totpToken has been deprecated, use --mfaTotpToken instead`.

## Session keys

The session keys found while reading resources are saved to the server before the CLI logs out.
It then prints `Saved N session keys to server` on stderr.

## Related

- [Authentication](authentication.md): `verify`, MFA.
- [TLS and proxies](tls.md): certificates, mutual TLS, proxies.
- [Troubleshooting](troubleshooting.md): settings that are missing or refused.
- [Security](../security.md#the-config-file): what the config file holds.
