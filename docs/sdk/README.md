---
title: Overview
sidebar_position: 1
---

# The SDK

One Rust library, `passbolt-sdk`, and two thin layers that make it callable from other languages:

```text
                    passbolt-sdk (Rust: login, crypto, API)
                   /                                    \
     passbolt-ffi (UniFFI)                        passbolt-wasm (wasm-bindgen)
     Python, Java, Android/Kotlin,                JavaScript, TypeScript
     .NET, Go, Ruby, Swift                        (browsers, extensions, Node 20+)
```

The encryption, the GPGAuth login and the Passbolt API calls are the same code in every language:
only the way they are called differs.

| Language | Page | Calls |
|---|---|---|
| Rust | [Rust](rust.md) | `async` |
| JavaScript / TypeScript | [JavaScript](javascript.md) | `async` (promises) |
| Python | [Python](python.md) | blocking |
| Java | [Java](java.md) | blocking |
| Android (Kotlin) | [Android](android.md) | blocking |
| .NET (C#) | [.NET](dotnet.md) | blocking |
| Go | [Go](go.md) | blocking |
| Ruby | [Ruby](ruby.md) | blocking |
| Swift (iOS) | [Swift](swift.md) | blocking |

The blocking bindings run the network calls on their own runtime: on mobile, call them off the
main thread.

## Concepts

**Session.** `login` takes the server URL, the armored OpenPGP private key of the account and its
passphrase, runs GPGAuth and returns a client holding the session. `logout` ends it.

**Pinning.** `fetchServerKey` / `fetch_server_key` returns the server key and its fingerprint,
computed from the key. Show the fingerprint to the user once, save the key, then give it to each
login (`serverPublicKey` / `server_public_key`): the server must then prove it holds the private
key, and another server answering at the same address is refused. The same goes for the shared
metadata key (`metadataKeyFingerprint` / `metadata_key_fingerprint`).

**Resources and views.** A v5 resource keeps its name, username and URIs encrypted. The
*resource views* (`getResourceView`, `listResourceViews`, `get_resource_view`,
`list_resource_views`) decrypt them, and the secret on request, for every resource type: prefer
them to the raw resources. The FFI bindings return views as JSON text, to parse with the JSON
library of the language.

**Writes.** `createResource` / `create_resource` takes the fields of the resource, as an object in
JavaScript and as JSON text in the FFI bindings: `{"name": …, "username"?, "uris"?, "description"?,
"password"?, "totp"?, "note"?, "pin_code"?, "custom_fields"?, "folder_parent_id"?, "expired"?,
"resource_type"?, "metadata_fields"?, "secret_fields"?}`. The
type follows the fields and the server's default version when not given. `updateResource` /
`update_resource` takes only the fields to change.

**Sharing.** Permission types are Passbolt's: `1` read, `7` update, `15` owner, `-1` to revoke.

**Errors.** Rust returns `PassboltError`; JavaScript throws an `Error` with the message; the FFI
bindings raise the `PassboltFfiError` of the language (`PassboltFfiException` in Kotlin), whose
variants say what failed: `Auth`, `Crypto`, `Api` (with the HTTP status), `NotFound`,
`Transport`, `Config`, `InvalidArgument`, `Other`.

## What the API covers

The same operations in every language:

- Session: login (MFA with a TOTP code or secret, pinned keys, TLS options), logout, keep-alive,
  session check.
- Resources: list (search, favorites, owned), get, views, create, update, delete, share, move,
  permissions, decrypt a secret.
- Folders: list, tree, create, rename, delete (with their content), share, move, permissions.
- Users and groups: list, get, create, update, delete, delete blockers and deletion with an
  ownership transfer.
- Tags, comments, favorites, password expiry settings, metadata settings, resource types.
- Have I Been Pwned check, and stateless OpenPGP helpers (`encryptMessage`, `decryptMessage`,
  `getKeyFingerprint`).
