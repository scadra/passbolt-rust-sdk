---
title: generate
sidebar_position: 11
---

# generate

Generate a password, a passphrase or a PIN code as the browser extension does, from the password
policies of your organization.

The policies are the settings an administrator chose, or those of Passbolt. The flags of each
command replace these settings; the settings you do not give are kept.

## generate

Generate a secret with the default generator of the organization: a password or a passphrase.

```bash
passbolt generate [flags]
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `--offline` | No | Use the default policies of Passbolt, without logging in or a configuration. Works with every `generate` command. |

The secret alone goes to stdout, for a script. With `--json`, its entropy in bits and the strength
the extension would show come too.

The strengths are those of the extension: `very-weak` (under 60 bits), `weak` (from 60), `fair`
(from 80), `strong` (from 112) and `very-strong` (from 128).

### Examples

#### Put a secret in a variable

```bash
PASSWORD=$(passbolt generate)
```

#### See the entropy and strength

```bash
passbolt --json generate
```

```text
{
  "entropy": 116.56,
  "secret": "eh5{\";gw]s~H\"3!5qb",
  "strength": "strong"
}
```

#### Generate without a server

```bash
passbolt generate --offline
```

## generate password

Generate a password from character sets.

```bash
passbolt generate password [flags]
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `-l, --length <N>` | No | Number of characters, 8 to 128. Default: the organization's (18 in Passbolt's policies). |
| `--charset <SET>` | No | Sets to draw from, replacing the organization's. Repeat it, or separate the sets with commas: `upper` (A-Z), `lower` (a-z), `digit` (0-9), `parenthesis` (`{[(\|)]}`), `char1` (`#$%&@^~`), `char2` (`.,:;`), `char3` (`'"` and the backtick), `char4` (`/\_-`), `char5` (`<*+!?=`), `emoji` (the emoticons of Unicode 6). |
| `--include-look-alike` | No | Keep the look-alike characters `O l \| I 0 1`, left out by default. |

### Examples

#### Generate a 32-character password of letters and digits

```bash
passbolt generate password --length 32 --charset upper,lower,digit
```

## generate passphrase

Generate a passphrase of words of the EFF list.

```bash
passbolt generate passphrase [flags]
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `-w, --words <N>` | No | Number of words, 4 to 40. Default: the organization's (9 in Passbolt's policies). |
| `-s, --separator <TEXT>` | No | Text between the words. Default: the organization's (a space in Passbolt's policies). |
| `--case <CASE>` | No | `lowercase`, `uppercase` or `camelcase`. Default: the organization's. |

### Examples

#### Generate a six-word passphrase

```bash
passbolt generate passphrase --words 6 --separator - --case camelcase
```

## generate pin

Generate a PIN code.

```bash
passbolt generate pin [flags]
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `-l, --length <N>` | No | Number of digits, 4 to 12. Default: `4`. |

### Examples

#### Generate a six-digit PIN code

```bash
passbolt generate pin --length 6
```

## Create a resource with a generated password

`create resource --generate` and `update resource --generate` set a password generated from the
policies of the organization, as the extension fills a new password:

```bash
passbolt create resource --name "Database" --username admin --generate
passbolt update resource --id <UUID> --generate
```

## Related

- [Resources](resources.md): `create resource` and `update resource`.
- [Output](../output.md): `--json` output.
