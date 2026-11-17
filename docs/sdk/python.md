---
title: Python
sidebar_position: 4
---

# Python

Use the `passbolt` package to log in to Passbolt and read, write and share secrets from Python,
with blocking calls or asyncio.

## Installation

The package is on PyPI as `switch-case-passbolt-sdk`. It needs Python 3.9 or later, on Linux
(x86_64, aarch64), macOS or Windows.

```bash
pip install switch-case-passbolt-sdk
```

You import it as `passbolt`. It ships type hints (`py.typed`).

## Initialize

Log in with `passbolt.Client.login`. Its calls block; for asyncio, see [Async calls](#async-calls).

```python
import os

import passbolt

with open("private.asc") as key_file:
    private_key = key_file.read()

with passbolt.Client.login(
    "https://passbolt.example.com", private_key, os.environ["PASSBOLT_PASSPHRASE"]
) as client:
    for view in client.list_resource_views("github"):
        print(view.id, view.name, view.username)
```

The `with` block logs out at the end; without it, call `client.logout()`. A failed logout raises
its `PassboltError`, unless the block is already leaving on an exception.

## Login options

`login` takes these keywords after the URL, the key and the passphrase. Every keyword is optional.

| Keyword | Type | Description |
|---|---|---|
| `server_public_key` | `str` | The armored server key pinned with `passbolt.fetch_server_key`. |
| `metadata_key_fingerprint` | `str` | The pinned fingerprint of the shared metadata key. |
| `mfa_totp_token` | `str` | The base32 TOTP secret, for an account with TOTP. |
| `timeout_seconds` | `int` | Seconds a request may take. Default: 60; `0` waits forever. |
| `tls_skip_verify` | `bool` | Skip the certificate check. Default: `False`. |
| `proxy` | `str` | The proxy URL. |
| `client_certificate_pem`, `client_key_pem` | `str` | The PEM certificate and key, for mTLS. |

### Pin the server key

```python
server_key = passbolt.fetch_server_key("https://passbolt.example.com")
print("Check this fingerprint with your administrator:", server_key.fingerprint)

client = passbolt.Client.login(
    "https://passbolt.example.com",
    private_key,
    passphrase,
    server_public_key=server_key.armored_key,
    mfa_totp_token=None,          # the base32 TOTP secret, for an account with TOTP
    metadata_key_fingerprint=None,
    timeout_seconds=None,         # 60 by default, 0 waits forever
    tls_skip_verify=False,
    proxy=None,
    client_certificate_pem=None,  # and client_key_pem, for mTLS
)
```

## Read resources

The calls return typed objects: `passbolt.ResourceView`, `passbolt.Resource`, `passbolt.Folder`,
`passbolt.User`… A `ResourceView` holds the fields every resource type shares, decrypted; the
others, custom fields and icon among them, are the JSON objects `metadata_json` and
`secret_json`.

### Read a password

```python
view = client.get_resource_view(resource_id)
print(view.password)
```

## Create and share resources

`create_resource` takes a `passbolt.NewResource`, `update_resource` a `passbolt.ResourceChanges`.
The fields you leave out keep their default. `passbolt.PermissionType` holds `READ`, `UPDATE`,
`OWNER` and `REVOKE`.

### Create, update, share and move a resource

```python
created = client.create_resource(
    passbolt.NewResource(name="GitHub", username="ada", password="…")
)
client.update_resource(created.id, passbolt.ResourceChanges(password="new"))
client.share_resource(created.id, passbolt.PermissionType.UPDATE, user_ids=[user_id])

folder = client.create_folder("Ops")
client.move_resource(created.id, folder.id)
```

## Generate a password

Generate passwords from character sets, passphrases of words of the EFF list, and PIN codes, as
the browser extension does. Start from the password policies of the organization or from settings
of your own: a setting you leave out keeps the default of Passbolt.

### Generate secrets and rate them

```python
policies = client.get_password_policies()  # the organization's: generator and settings
secret = passbolt.generate_secret(policies)

password = passbolt.generate_password(passbolt.PasswordGeneratorSettings(length=24))
passphrase = passbolt.generate_passphrase(
    passbolt.PassphraseGeneratorSettings(words=6, word_case=passbolt.WordCase.CAMELCASE)
)
pin_code = passbolt.generate_pin_code(6)

print(passbolt.secret_strength(password))  # Strength.VERY_STRONG, as the extension shows it
print(passbolt.secret_entropy(password))   # in bits
```

Without arguments, `generate_password` and `generate_secret` use the defaults of Passbolt: 18
characters of every set but emoji. `generate_passphrase` gives 9 lowercase words joined by spaces.

## Handle errors

`passbolt.PassboltError` is the base of `TransportError`, `AuthError`, `CryptoError`, `ApiError`
(with the HTTP `status`), `NotFoundError`, `ConfigError` and `InvalidArgumentError`.

### Catch a crypto error and an API error

```python
try:
    passbolt.get_key_fingerprint("not a key")
except passbolt.CryptoError as error:
    print("not a key:", error)
except passbolt.ApiError as error:
    print("the server answered", error.status, error.reason)
except passbolt.PassboltError as error:
    print("failed:", error)
```

## Async calls

`passbolt.AsyncClient` has the methods of `Client` as coroutines, and the same login keywords.
The requests run on the SDK's own threads: the event loop goes on meanwhile, and
`asyncio.gather` runs several at once. `async with` logs out at the end, as `with` does.

### Run two requests at once

```python
import asyncio

import passbolt


async def names(private_key: str, passphrase: str) -> list[str]:
    async with await passbolt.AsyncClient.login(
        "https://passbolt.example.com", private_key, passphrase
    ) as client:
        views, folders = await asyncio.gather(
            client.list_resource_views("github"), client.list_folders()
        )
        print(len(folders), "folders")
        return [view.name for view in views]
```

## Method names

The methods are those of the [overview](README.md#what-the-api-covers), in snake_case:
`list_folders`, `create_folder`, `delete_user_with_transfer`, `set_resource_tags`… The optional
arguments have defaults (`list_resources(favorites_only=True)`). The generated bindings stay
available as `passbolt._ffi`.

## Related

- [Overview](README.md): the concepts shared by every language.
- [API reference](api.md): every method, function and record.
- [Upgrading](upgrading.md): the breaking changes since the 0.1.1 packages.
