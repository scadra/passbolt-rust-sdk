---
title: Coming from go-passbolt-cli
sidebar_position: 7
---

# Coming from go-passbolt-cli

`passbolt` takes go-passbolt-cli's command lines, flags (`--serverAddress`, `--folderParentID`…),
environment variables (`SERVERADDRESS`…), config file and `--filter` expressions, and prints the
same tables, JSON and messages. On top of that it keeps its own flag names, `PASSBOLT_*`
variables and extra commands and columns.

## What carries over

- **Config file**: without `~/.config/passbolt/config.toml`, go-passbolt-cli's
  `~/.config/go-passbolt-cli/go-passbolt-cli.{json,toml,yaml,yml}` is read, and `configure` /
  `verify` update it with its own keys. See [configuration](configuration.md).
- **Flags**: every camelCase flag (`--serverAddress`, `--userPrivateKeyFile`, `--mfaTotpToken`,
  `--tlsSkipVerify`…), the deprecated `--totpToken` / `--totpOffset` with a warning, and the
  command aliases (`new`, `read`, `index`, `ls`, `filter`, `search`, `change`, `remove`).
- **Variables**: `SERVERADDRESS`, `USERPRIVATEKEY`, `USERPASSWORD`, `MFAMODE`… (the flag name in
  capitals), after the `PASSBOLT_*` ones.
- **Filters**: the same CEL expressions, with the same variables. See [filters](filters.md).
- **Output**: the same tables, JSON fields, `get` key-values and `create` messages. See
  [output](output.md).
- **Server verification**: go-passbolt-cli's `server_verify_token` is checked and saved, so both
  CLIs share a verified config file.

## What differs on purpose

Where go-passbolt-cli would weaken the account or lose data:

- The server address must use HTTPS, except on localhost.
- Non-interactive MFA tries at most 3 codes: the server disables the account after too many.
- `create folder` in a shared folder gives it the folder's permissions, as the browser extension
  does.
- `delete user` and `delete group` first check what the user or group alone owns, and refuse
  until `--transfer-to` gives it to someone.
- `export keepass` refuses an empty password, keeps the folders as groups, and derives the KDBX
  3.1 key with 60,000 rounds instead of 6,000.
- `list resource` lists every resource type, and skips a resource that cannot be read (a secret
  that does not decrypt…) with a `Warning: resource <id> skipped: …` line, where go-passbolt-cli
  stops with an error.
- Prompts go to stderr, so that `--json` output stays clean.
