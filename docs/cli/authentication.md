---
title: Authentication and MFA
sidebar_position: 3
---

# Authentication and MFA

Log in with your OpenPGP key, pin the identity of your server, and answer MFA from a terminal
or a script.

## GPGAuth

The CLI logs in with **GPGAuth**, as the browser extension does, then keeps the session cookie:

1. Once `passbolt verify` pinned the server key, the server first proves it holds its private
   key: it must decrypt a fresh token (`POST /auth/verify.json`).
2. The CLI sends `POST /auth/login.json` with the fingerprint of your key. The server answers
   with a challenge encrypted for you.
3. The CLI decrypts it, checks it is a GPGAuth token, and sends it back.
4. The server sets the session cookie. The requests that follow carry the CSRF token.

Each answer must carry the `X-GPGAuth-*` headers of its step (version 1.3.0, progress,
authenticated flag), which the browser extension checks too. A proxy or another server answering
instead of Passbolt is refused.

After login, the CLI checks that the server's copy of your public key matches your private key.

## Pinning the server: `verify`

Pin the server key and the shared metadata key in the config file, then print
`Verification Enabled`.

```bash
passbolt verify [flags]
```

`verify` also saves the settings given, as [`configure`](configuration.md#saving-settings-configure)
does. It needs no MFA, and asks for the passphrase when it is not given.

### Flags

| Flag | Required | Description |
|---|---|---|
| `--force` | No | Trust a server key or metadata key that changed since it was pinned. Use it only once your administrator confirmed the change. |

### What `verify` pins

- **The server key**, once the server proved it holds the private key. Each login then checks it
  again. Its fingerprint is computed from the key, not taken from the server.
- **The active shared metadata key**: shared metadata is only encrypted for it. It is pinned only
  when the account logs in without MFA.
- **The verification tokens** `server_verify_token` and `server_verify_enc_token`, checked at
  each login.

A pinned key that changed is refused until you run `verify --force`.

### Examples

#### Pin the server's identity

```bash
passbolt verify
```

```text
Verification Enabled
```

#### Trust a new server key

```bash
passbolt verify --force
```

:::caution
Run `--force` only once your administrator confirmed the key change. Otherwise you may trust
another server answering at the same address.
:::

## MFA

Choose how the CLI answers MFA with `--mfa-mode` (`mfa_mode` in the config file). Three modes are
supported: `interactive-totp`, `noninteractive-totp` and `none`.

### Type the TOTP code: `interactive-totp`

The default. The CLI asks for the code on stderr (`Enter TOTP:`) and reads it from the terminal,
or from stdin when stdin is not a terminal.

- You get 3 attempts. After a refused code, it prints `TOTP Verification Failed` (on stdout).
- The passphrase is asked for the same way (`Enter Password:`) when not given.

### Compute the code from the secret: `noninteractive-totp`

Give the TOTP *secret*, not the 6-digit code, in the config or the environment. The CLI computes
the current code. The mode is also spelt `non-interactive-totp`.

```bash
passbolt list resource \
  --mfa-mode noninteractive-totp \
  --mfa-totp-token "JBSWY3DPEBLW64TMMQ======"
```

- `--mfa-totp-offset` compensates for clock drift.
- A new attempt waits for the next TOTP code: the same code is never sent twice.

### Disable MFA: `none`

For accounts without MFA. Any other mode is read as `none`.

### Limits

- The server disables an account after too many wrong codes. The CLI sends at most 3 per
  session, whatever `--mfa-retrys` says, and stops as soon as the server ends the session.
- An account whose MFA is not TOTP (Yubikey, Duo…) gets an error naming the MFA it has.

## Related

- [Configuration](configuration.md): every setting and its variable.
- [Troubleshooting](troubleshooting.md#mfa): MFA and server key errors.
- [Security](../security.md): what pinning protects against.
- [CI guide](../guides/ci.md): MFA in a pipeline.
