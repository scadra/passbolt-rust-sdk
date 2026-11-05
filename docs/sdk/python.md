---
title: Python
sidebar_position: 4
---

# Python

```bash
pip install switch-case-passbolt-sdk
```

Python 3.9 or later, on Linux (x86_64, aarch64), macOS and Windows. The package is `passbolt`;
its calls block. It ships type hints (`py.typed`).

## Log in and list

```python
import os

import passbolt

with open("private.asc") as key_file:
    private_key = key_file.read()

with passbolt.Client.login(
    "https://passbolt.example.com", private_key, os.environ["PASSBOLT_PASSPHRASE"]
) as client:
    for view in client.list_resource_views("github"):
        print(view["id"], view["name"], view["username"])
```

The `with` block logs out at the end; without it, call `client.logout()`.

## Pinning the server, MFA, TLS

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

Every keyword is optional.

## Reading and writing

```python
view = json.loads(client.get_resource_view(resource_id))
print(view["password"])

created = client.create_resource(json.dumps({"name": "GitHub", "username": "ada", "password": "…"}))
client.update_resource(created.id, json.dumps({"password": "new"}))
client.share_resource(created.id, [user_id], [], 7)
```

## Errors

```python
try:
    passbolt_ffi.get_key_fingerprint("not a key")
except passbolt_ffi.PassboltFfiError.Crypto as error:
    print("not a key:", error.reason)
except passbolt_ffi.PassboltFfiError.Api as error:
    print("the server answered", error.status)
```

The methods are those of the [overview](README.md#what-the-api-covers), in snake_case:
`list_folders`, `create_folder`, `delete_user_with_transfer`, `set_resource_tags`…
