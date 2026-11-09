---
title: generate
sidebar_position: 11
---

# generate

Generate a password, a passphrase or a PIN code as the browser extension does: from the password
policies of the organization, the settings an administrator chose (or those of Passbolt).

```bash
passbolt generate                 # the default generator of the organization
passbolt generate password        # a password, from the organization's password settings
passbolt generate passphrase      # a passphrase of words of the EFF list
passbolt generate pin --length 6  # a PIN code, 4 to 12 digits
```

The secret alone goes to stdout, for a script: `PASSWORD=$(passbolt generate)`. With `--json`,
its entropy in bits and the strength the extension would show come too:

```bash
$ passbolt --json generate
{
  "entropy": 116.56,
  "secret": "eh5{\";gw]s~H\"3!5qb",
  "strength": "strong"
}
```

The strengths are those of the extension: `very-weak` (under 60 bits), `weak` (60), `fair`
(80), `strong` (112) and `very-strong` (128).

## Options

The options replace the settings of the organization; those not given keep them.

| Command | Option | Description |
|---|---|---|
| `password` | `-l, --length <N>` | Number of characters, 8 to 128 (18 by default) |
| | `--charset <SET>` | Sets to draw from, repeated or separated by commas: `upper`, `lower`, `digit`, `parenthesis` (`{[(\|)]}`), `char1` (`#$%&@^~`), `char2` (`.,:;`), `char3` (`'"` and the backtick), `char4` (`/\_-`), `char5` (`<*+!?=`), `emoji` |
| | `--include-look-alike` | Keep `O l \| I 0 1`, left out by default |
| `passphrase` | `-w, --words <N>` | Number of words, 4 to 40 (9 by default) |
| | `-s, --separator <TEXT>` | Text between the words (a space by default) |
| | `--case <CASE>` | `lowercase`, `uppercase` or `camelcase` |
| `pin` | `-l, --length <N>` | Number of digits, 4 to 12 (4 by default) |
| all | `--offline` | The default policies of Passbolt, without logging in or a configuration |

```bash
passbolt generate password --length 32 --charset upper,lower,digit
passbolt generate passphrase --words 6 --separator - --case camelcase
passbolt generate --offline
```

## Creating with a generated password

`create resource --generate` and `update resource --generate` set a password generated from the
policies of the organization, as the extension fills a new password:

```bash
passbolt create resource --name "Database" --username admin --generate
passbolt update resource --id <UUID> --generate
```
