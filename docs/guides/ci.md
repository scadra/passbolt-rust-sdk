---
title: CI pipelines
sidebar_position: 2
---

# CI pipelines

Run the CLI in GitHub Actions or GitLab CI with an account of its own, and hand secrets to your
jobs without printing them.

The CLI reads all its settings from `PASSBOLT_*` variables, so a pipeline needs no config file.
The secrets come from the secret store of your CI, and `passbolt exec` hands them to the job.

## Prerequisites

- The `passbolt` CLI on a trusted machine, to create the account and read the server key. See
  [installation](../getting-started/installation.md).
- A place in your CI for secrets and variables: repository or environment secrets on GitHub,
  CI/CD variables on GitLab.

## 1. Create a dedicated account

Create a Passbolt user for the CI, with its own OpenPGP key, instead of using a person's account:

```bash
passbolt create user --username ci@example.com --firstname CI --lastname Pipeline --role user
```

The user then completes the setup in the browser extension, as any user does, and exports its
private key from there.

A dedicated account keeps the pipeline apart from people:

- Share with it only the resources the pipeline reads, with the `1` (read) permission. A group
  such as `ci` makes this easy to review. See [sharing](sharing.md).
- Its key and passphrase live only in the CI secret store. If they leak, disable or delete this
  user and nobody else is affected.
- Its actions show under its own name on the server.

## 2. Pin the server key

`passbolt verify` saves the server key in a config file, and each later login checks that the
server holds the matching private key. A CI job starts with no config file, so you give it the
key in `PASSBOLT_SERVER_PUBLIC_KEY` instead.

Get the key once, from a trusted machine, with the settings of the CI account:

```bash
export PASSBOLT_SERVER_ADDRESS=https://passbolt.example.com
export PASSBOLT_USER_PRIVATE_KEY_FILE=ci-private.asc
passbolt --config ./ci.toml verify
```

`ci.toml` now holds `server_public_key`, and `metadata_key_fingerprint` when the account has no
MFA. Secrets given by a variable are never written to it.

1. Copy the value of `server_public_key` (the armored block, without the quotes) into the CI
   variable `PASSBOLT_SERVER_PUBLIC_KEY`.
2. If the pipeline writes shared resources, copy `metadata_key_fingerprint` into
   `PASSBOLT_METADATA_KEY_FINGERPRINT`.
3. Delete `ci.toml`.

With the key set, a login to a server that cannot decrypt a fresh token for it fails. After a
change of the server key, confirmed by your administrator, run `verify --force` again and update
the variable.

## 3. Store the settings

| Variable | Content | Where it comes from |
|---|---|---|
| `PASSBOLT_SERVER_ADDRESS` | `https://passbolt.example.com` | CI variable |
| `PASSBOLT_USER_PRIVATE_KEY` | The armored private key of the CI account | CI secret |
| `PASSBOLT_USER_PRIVATE_KEY_FILE` | Or: the path of a file holding it | CI secret file |
| `PASSBOLT_USER_PASSWORD` | Its passphrase | CI secret |
| `PASSBOLT_SERVER_PUBLIC_KEY` | The pinned server key, from step 2 | CI variable |
| `PASSBOLT_MFA_MODE` | `noninteractive-totp` when the account has TOTP | CI variable |
| `PASSBOLT_MFA_TOTP_TOKEN` | The TOTP secret of the account | CI secret |

Every setting of [configuration](../cli/configuration.md) has such a variable. An empty variable
counts as unset.

:::caution
Without `PASSBOLT_USER_PASSWORD`, the CLI asks for the passphrase on stdin, and the job fails on
`EOF`.
:::

## 4. Answer MFA

If the account has TOTP, set `PASSBOLT_MFA_MODE=noninteractive-totp` and put the TOTP secret in
`PASSBOLT_MFA_TOTP_TOKEN`: the base32 secret of the authenticator setup, not a 6-digit code. The
CLI computes the code.

- If the runner clock drifts, set `PASSBOLT_MFA_TOTP_OFFSET`, for example `-30s`.
- The CLI sends at most 3 codes per session.

An account without MFA can keep the default mode: no code is asked for when the server does not
ask. See [MFA](../cli/authentication.md#mfa).

## 5. Add the job

Both examples install a pinned version of the CLI, check it, and run `deploy.sh` through
`passbolt exec`.

- The release archives are named `passbolt-cli-<version>-<target>.tar.gz`. The musl one runs on
  any x86_64 Linux. Pin the version, and check the archive against `SHA256SUMS`.
- `deploy.sh` finds the decrypted password in `$DB_PASSWORD`. See [injecting secrets](exec.md).

### GitHub Actions

Store `PASSBOLT_USER_PRIVATE_KEY`, `PASSBOLT_USER_PASSWORD` and `PASSBOLT_MFA_TOTP_TOKEN` as
repository or environment secrets. Store `PASSBOLT_SERVER_ADDRESS`, `PASSBOLT_SERVER_PUBLIC_KEY`
and `DB_RESOURCE_ID` as variables.

```yaml title=".github/workflows/deploy.yml"
name: Deploy

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      PASSBOLT_SERVER_ADDRESS: ${{ vars.PASSBOLT_SERVER_ADDRESS }}
      PASSBOLT_SERVER_PUBLIC_KEY: ${{ vars.PASSBOLT_SERVER_PUBLIC_KEY }}
      PASSBOLT_MFA_MODE: noninteractive-totp
    steps:
      - uses: actions/checkout@v4

      - name: Install the Passbolt CLI
        env:
          VERSION: "0.1.2"
        run: |
          archive="passbolt-cli-${VERSION}-x86_64-unknown-linux-musl.tar.gz"
          base="https://github.com/scadra/passbolt-rust-sdk/releases/download/v${VERSION}"
          curl -fsSLO "$base/$archive"
          curl -fsSLO "$base/SHA256SUMS"
          sed -n "s|^\([0-9a-f]*\) .*${archive}\$|\1  ${archive}|p" SHA256SUMS | sha256sum -c -
          tar xzf "$archive"
          sudo install "${archive%.tar.gz}/passbolt" /usr/local/bin/
          passbolt --version

      - name: Deploy
        env:
          PASSBOLT_USER_PRIVATE_KEY: ${{ secrets.PASSBOLT_USER_PRIVATE_KEY }}
          PASSBOLT_USER_PASSWORD: ${{ secrets.PASSBOLT_USER_PASSWORD }}
          PASSBOLT_MFA_TOTP_TOKEN: ${{ secrets.PASSBOLT_MFA_TOTP_TOKEN }}
          DB_PASSWORD: passbolt://${{ vars.DB_RESOURCE_ID }}
        run: passbolt exec -- ./deploy.sh
```

The secrets are given to the step that needs them, not to the whole job: other steps, and the
actions they run, do not see them.

### GitLab CI

Under **Settings > CI/CD > Variables**, add:

- `PASSBOLT_SERVER_ADDRESS`, `PASSBOLT_SERVER_PUBLIC_KEY` and `DB_RESOURCE_ID`, as plain
  variables.
- `PASSBOLT_USER_PRIVATE_KEY_FILE`, of type **File**, holding the private key. GitLab writes it
  to a file and puts the path of that file in the variable.
- `PASSBOLT_USER_PASSWORD` and `PASSBOLT_MFA_TOTP_TOKEN`, **masked** and **protected**.

A masked variable must fit on one line, which an armored key does not: hence the File variable.

```yaml title=".gitlab-ci.yml"
deploy:
  image: alpine:3.20
  variables:
    PASSBOLT_CLI_VERSION: "0.1.2"
    PASSBOLT_MFA_MODE: noninteractive-totp
    DB_PASSWORD: passbolt://$DB_RESOURCE_ID
  before_script:
    - apk add --no-cache curl
    - archive="passbolt-cli-${PASSBOLT_CLI_VERSION}-x86_64-unknown-linux-musl.tar.gz"
    - base="https://github.com/scadra/passbolt-rust-sdk/releases/download/v${PASSBOLT_CLI_VERSION}"
    - curl -fsSLO "$base/$archive"
    - curl -fsSLO "$base/SHA256SUMS"
    - sed -n "s|^\([0-9a-f]*\) .*${archive}\$|\1  ${archive}|p" SHA256SUMS | sha256sum -c -
    - tar xzf "$archive"
    - install "${archive%.tar.gz}/passbolt" /usr/local/bin/
  script:
    - passbolt exec -- ./deploy.sh
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

GitLab gives protected variables only to pipelines of protected branches and tags, so the rule
above runs the job on the default branch only.

## Keep secrets out of the logs

- Prefer `passbolt exec`: the secret goes into the environment of the command, never into the
  log or the command line.
- GitHub masks the value of each secret in the log, line by line. A value the job builds itself
  is not masked: register it before it can be printed.

  ```bash
  token=$(passbolt get resource --id "$TOKEN_RESOURCE_ID" --json | jq -r .password)
  echo "::add-mask::$token"
  ```

- GitLab masks the masked variables only. A password read with `get resource` is not one of them.
- Do not run `set -x` in a script that handles a secret: the shell prints each command with its
  arguments.
- Do not pass a secret as an argument (`--password "$value"`): other processes of the runner can
  read the command line.
- `--debug` prints the requests and the settings, never the secrets. `passbolt exec --debug`
  names each variable it fills, not its value.
- Do not write a secret to `$GITHUB_ENV`, an artifact or the cache: they outlive the job.

## Next steps

- [Injecting secrets](exec.md): hand secrets to Docker, Terraform or Ansible.
- [Scripting](scripting.md): read the JSON output with `jq`.
- [Configuration](../cli/configuration.md): every `PASSBOLT_*` variable.
- [Authentication](../cli/authentication.md#mfa): MFA modes.
