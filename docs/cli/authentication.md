---
title: Authentication and MFA
sidebar_position: 3
---

# Authentication and MFA

## GPGAuth

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

## Pinning the server: `verify`

Pin the server key and the shared metadata key in the config file, with the settings given (as
[`configure`](configuration.md#saving-settings-configure)), then print `Verification Enabled`.
Needs no MFA; the password is asked for when it is not given.

```bash
passbolt verify
passbolt verify --force   # trust keys that changed, once your administrator confirmed it
```

- The server key is pinned once the server proved it holds the private key; each login then
  checks it again. Its fingerprint is computed from the key, not taken from the server.
- The active shared metadata key is pinned: shared metadata is only encrypted for it. It is
  pinned only when the account logs in without MFA.
- A pinned key that changed is refused until `--force`.
- go-passbolt-cli's `server_verify_token` / `server_verify_enc_token` are saved too: either CLI
  checks the server with the same config file.

## MFA

Three modes are supported.

**`interactive-totp`** (default) asks for the TOTP code on stderr (`Enter TOTP:`), read from the
terminal or, when stdin is not one, from stdin; 3 attempts, `TOTP Verification Failed` after a
refused code. The password is asked for the same way (`Enter Password:`) when not given.

**`noninteractive-totp`** (also spelt `non-interactive-totp`) takes the TOTP *secret* (not the
6-digit code) in the config or the environment:

```bash
passbolt list resource \
  --mfa-mode noninteractive-totp \
  --mfa-totp-token "JBSWY3DPEBLW64TMMQ======"
```

The CLI computes the current code. `--mfa-totp-offset` compensates for clock drift. A new
attempt waits for the next TOTP code: the same code is never sent twice.

The server disables an account after too many wrong codes: the CLI sends at most 3 per session,
whatever `--mfa-retrys` says (go-passbolt-cli sends `--mfaRetrys` + 1), and stops as soon as the
server ends the session. An account without TOTP (Yubikey, Duo…) gets an error naming the MFA it
has.

**`none`** disables MFA, for accounts without it. Any other mode is `none`, as for
go-passbolt-cli.
