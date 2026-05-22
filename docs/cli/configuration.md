---
title: Configuration
sidebar_position: 2
---

# Configuration

## Config file

`~/.config/passbolt/config.toml`. When it does not exist, the config file of go-passbolt-cli is
read (and `configure` / `verify` update it, with its keys):
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

## Priority order

CLI flags > `PASSBOLT_*` variables > go-passbolt-cli variables (`SERVERADDRESS`,
`USERPASSWORD`, `MFAMODE`…: the flag name in capitals) > config file > defaults.

Durations use Go's syntax (`30s`, `1m30s`, `500ms`, `-1m`); a plain number is seconds.
Booleans take `--debug`, `--debug=true` or `--debug=false`; in a variable or a file also `1`,
`0`, `t`, `f`. An invalid go-passbolt-cli variable is ignored, as go-passbolt-cli does
(`DEBUG=*` does not stop the CLI); an invalid `PASSBOLT_*` variable is an error.

## Saving settings: `configure`

`passbolt configure` saves every setting in effect (flags, variables, config file, defaults),
silently; `--debug` prints what was saved, secrets masked.

```bash
passbolt configure --serverAddress https://passbolt.example.org \
  --userPrivateKeyFile keys/privatekey.asc --userPassword '1234'
```

The private key file is read: its content is saved, not its path. The secrets set by a variable
(password, TOTP secret, private keys) are never saved: a secret exported for one command never
ends up on disk. Give a secret on the command line to save it.

## Global flags

These flags apply to every command and can be set by flag, variable or config file. Each flag
also takes go-passbolt-cli's spelling (`--serverAddress`, `--userPrivateKeyFile`,
`--mfaTotpToken`, `--tlsSkipVerify`…), and each setting go-passbolt-cli reads from the
environment is also read from its variable (`SERVERADDRESS`, `USERPRIVATEKEY`, `MFATOTPTOKEN`…).
go-passbolt-cli's deprecated `--totpToken` and `--totpOffset` are taken with a warning.

| Flag | Variable | Default | Description |
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
| `--timeout` | `PASSBOLT_TIMEOUT` | `1m` | Time each request and the whole command may take (`0`: no limit); raise it to export a large vault |
| `--workers` | `PASSBOLT_WORKERS` | `0` (auto) | Parallel workers |
| `--debug` | `PASSBOLT_DEBUG` | `false` | Debug output on stderr: config file, files read, worker count, requests (no secrets) |
| `-j, --json` | — | `false` | JSON output |
| `-v, --version` | — | — | `passbolt version X (Built on DATE from Git SHA SHA)` |

The session keys found while reading resources are saved before logging out
(`Saved N session keys to server` on stderr).
