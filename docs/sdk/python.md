---
title: Python
sidebar_position: 4
---

# Python

```bash
pip install switch-case-passbolt-sdk
```

Python 3.9 or later, on Linux (x86_64, aarch64), macOS and Windows. The module is `passbolt_ffi`;
its calls block.

## Log in and list

```python
import json
import os

import passbolt_ffi

with open("private.asc") as key_file:
    private_key = key_file.read()

client = passbolt_ffi.PassboltClient.login(
    "https://passbolt.example.com", private_key, os.environ["PASSBOLT_PASSPHRASE"]
)
try:
    views = json.loads(client.list_resource_views("github", False))
    for view in views:
        print(view["id"], view["name"], view["username"])
finally:
    client.logout()
```

## Pinning the server, MFA, TLS

```python
server_key = passbolt_ffi.fetch_server_key("https://passbolt.example.com", False)
print("Check this fingerprint with your administrator:", server_key.fingerprint)

options = passbolt_ffi.FfiLoginOptions(
    tls_skip_verify=False,
    proxy=None,
    mfa_totp_token=None,               # the base32 TOTP secret, for an account with TOTP
    server_public_key=server_key.armored_key,
    metadata_key_fingerprint=None,
    timeout_seconds=None,              # 60 by default, 0 waits forever
    client_certificate_pem=None,
    client_key_pem=None,
)
client = passbolt_ffi.PassboltClient.login_with_config(
    "https://passbolt.example.com", private_key, passphrase, options
)
```

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
