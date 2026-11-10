---
title: Concepts
sidebar_position: 3
---

# Concepts

What the CLI and the SDK work with, in Passbolt's words. The commands are in the
[CLI reference](cli/commands/README.md), the calls in the [SDK](sdk/README.md) pages.

## Accounts and keys

Each Passbolt user has an **OpenPGP key pair**. The private key never leaves the client: it is
locked by the user's **passphrase**, and both are given to the CLI (config file, flag or
variable) or to `login` in the SDK. The server keeps the public key of every user, and has its
own key pair, the **server key**, which it uses for the login.

**Login (GPGAuth).** The client sends the fingerprint of the user's key; the server answers with
a random token encrypted for that key; the client decrypts it, checks it is a GPGAuth token, and
sends it back. The server then sets a session cookie. Once the server key is pinned, the server
first proves it holds the private server key, by decrypting a fresh token encrypted for it. See
[Authentication and MFA](cli/authentication.md) for the steps and the checks.

**Session and CSRF.** Requests after login carry the session cookie and an `X-CSRF-Token` header,
the value of the `csrfToken` cookie the server sets. A CLI command logs in, does its work and
logs out.

**MFA.** When the account has multi-factor authentication, the server asks for it after the
login. The CLI and the SDK answer with a TOTP code, typed or computed from the TOTP secret.
Other providers (Yubikey, Duo) are not supported: the error names the MFA the account has.

## Resources

A **resource** is an entry of the vault: a password, a TOTP, a note, a PIN code… It has two
parts:

- the **metadata**: name, username, URIs, and for some types the description, an icon and
  custom field names;
- the **secret**: password, TOTP, PIN code, secret note, custom field values. The secret is
  always encrypted.

### v4 and v5

| | v4 | v5 |
|---|---|---|
| Metadata | In clear on the server (`name`, `username`, `uri`, `description`) | Encrypted (`metadata`), for a metadata key |
| URIs | One | Up to 32 |
| Slugs | No prefix | `v5-` |

The organization's settings say which version new resources get by default and whether each
version may still be created. The CLI and the SDK read both.

### Resource types

Each resource has a **resource type**, known by its slug. It fixes which fields go in the
metadata and which in the secret. Fields marked as required must be set.

| Slug | Metadata | Secret |
|---|---|---|
| `password-string` | name, username, uri, description | the password alone, as a string |
| `password-and-description` | name, username, uri | password (required), description |
| `password-description-totp` | name, username, uri | password, totp (required), description |
| `totp` | name, uri | totp (required) |
| `v5-default` | name, username, uris, description, icon, custom fields | password (required), description, custom fields |
| `v5-default-with-totp` | name, username, uris, description, icon, custom fields | password, totp (required), description, custom fields |
| `v5-password-string` | name, username, uris, description, icon | the password alone, as a string |
| `v5-totp-standalone` | name, uris, description, icon | totp (required) |
| `v5-note` | name, uris, description, icon | description (required): the secret note |
| `v5-pin-code` | name, description, icon | pin_code (required, 4 to 12 digits), description |
| `v5-custom-fields` | name, uris, description, icon, custom fields (required) | custom fields (required) |

`v5-password-string` can be read but not created: the server refuses it.

**Choosing the type on create.** `--type` (`resource_type` in the SDK) names it. Without it, the
type follows the fields given and the server's default version:

| Fields given | v5 by default | v4 by default |
|---|---|---|
| password and TOTP | `v5-default-with-totp` | `password-description-totp` |
| password | `v5-default` | `password-and-description` |
| TOTP | `v5-totp-standalone` | `totp` |
| PIN code | `v5-pin-code` | — |
| custom fields | `v5-custom-fields` | — |
| note | `v5-note` | — |

Nothing secret is an error. Each create is checked against the schema of its type before
anything is encrypted.

**Upgrading.** [`migrate-metadata`](cli/commands/migrate-metadata.md) (administrators) turns v4
resources into v5: `password-string` becomes `v5-password-string`, `password-and-description`
`v5-default`, `password-description-totp` `v5-default-with-totp`, `totp` `v5-totp-standalone`.
The secrets keep their content.

## Metadata keys

v5 metadata is encrypted for one of two kinds of key:

| Key | `metadata_key_type` | Who can read | Used for |
|---|---|---|---|
| **Personal** (the user's own key) | `user_key` | The user alone | New resources, when the settings allow personal keys (the default) |
| **Shared metadata key** | `shared_key` | Every user holding a share of it | New resources when personal keys are not allowed, and every shared resource |

The shared metadata key is an OpenPGP key pair of the organization. Each user gets its private
key encrypted for their own key. Shared metadata is signed by the user and by the metadata key.
New shared metadata goes to the **active** key: the newest one, neither expired nor deleted,
that the user holds a share of.

Personal metadata cannot be shared: sharing a resource first re-encrypts its metadata for the
shared metadata key.

**Session keys.** Each encrypted message has a symmetric session key. After decrypting a
resource's metadata, the client keeps its session key, then saves the session keys to the
server, encrypted for the user (`/metadata/session-keys.json`), as the browser extension does.
The next reads use them instead of the slower public key decryption. A listing saves the new
ones at once; the CLI saves those found by other commands before logging out
(`Saved N session keys to server`). They are a cache: a session key that does not work is
ignored.

**Pinning.** [`passbolt verify`](cli/authentication.md#pinning-the-server-verify) saves the
fingerprint of the active shared metadata key (`metadata_key_fingerprint` in the SDK). New
shared metadata is then only encrypted for that key: another active key is refused until the
pin is updated.

## Secrets

A secret is encrypted for each user who can read the resource, one copy per user, and signed by
the user who wrote it. The server stores the copies; it cannot read them.

- **Create**: the secret is encrypted for the creator.
- **Share**: the users who gain access, group members included, get a new copy, decrypted by
  the sharing user then encrypted for each of them.
- **Group membership**: a user added to a group gets a copy of the secrets of the group's
  resources, encrypted by the user making the change.
- **Update**: a changed secret is encrypted again for every user with access.

## Permissions

| Type | Name | Allows |
|---|---|---|
| `1` | Read | Read the resource and its secret |
| `7` | Update | Also change and delete it |
| `15` | Owner | Also share it and move it |

`-1` in `share` revokes a permission.

A permission is given to a **user** or to a **group**. A group has members and **group
managers**, who manage its membership. A resource whose only permission is its owner's is
**personal**; the others are **shared**.

**Folders** hold resources and folders, and have permissions of their own. Folder names are in
clear. As the browser extension does:

- A resource or folder **created** in a folder gets exactly the folder's permissions.
- A resource or folder **moved** keeps the permissions it did not get from the folder it leaves,
  and gets those of the destination, the higher level winning. Moved to the root, the user who
  moves it keeps their permission. Only an owner can move it.
- A folder **shared** `--with-content` copies the change onto the sub-folders and resources
  below it that the user owns.

Each change of access sends the new secret copies needed with it.

## Expiry, tags, comments, favorites

- **Expiry**: a resource can have an expiry date (`--expiry`: a date, or a duration such as
  `90d`; `none` clears it). See [expiry dates](cli/filters.md#expiry-dates).
- **Tags** (Passbolt Pro): labels on resources, in clear. A tag starting with `#` is shared,
  the others are personal.
- **Comments**: messages on a resource, in clear, readable by those who can read it.
- **Favorites**: a per-user mark; `list resource --favorite` shows them.

The SDK has calls for all four; the CLI sets expiry dates and filters favorites.

## Password policies and the generator

The **password policies** of the organization (`/password-policies/settings.json`) choose the
default generator, password or passphrase, and the settings of each. The CLI and the SDK
generate passwords, passphrases and PIN codes from them, and measure their strength, as the
browser extension does. See [generate](cli/commands/generate.md).

## Glossary

| Term | Meaning |
|---|---|
| Active metadata key | The shared metadata key new shared metadata is encrypted for |
| CSRF token | The `csrfToken` cookie, sent back as the `X-CSRF-Token` header |
| Fingerprint | The 40 hexadecimal characters identifying an OpenPGP key |
| GPGAuth | Passbolt's login: a challenge encrypted for the user's key |
| Group manager | A group member who manages its membership |
| Metadata | Name, username, URIs… of a resource; encrypted in v5 |
| Passphrase | The password locking the user's private key |
| Personal key | The user's own key, used for metadata only they read |
| Pinning | Saving a key once, then refusing another one |
| Resource | An entry of the vault |
| Resource type | What fields a resource has, by slug |
| Secret | The encrypted part of a resource, one copy per user |
| Server key | The server's OpenPGP key, used to prove its identity at login |
| Session key | The symmetric key of one OpenPGP message |
| Shared metadata key | The organization's key for metadata shared between users |
| TOTP | Time-based one-time password, for MFA or stored in a resource |
