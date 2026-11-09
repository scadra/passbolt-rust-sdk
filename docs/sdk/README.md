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
| Python | [Python](python.md) | blocking, or `async` (`AsyncClient`) |
| Java | [Java](java.md) | blocking, or `CompletableFuture` (`AsyncPassboltClient`) |
| Android (Kotlin) | [Android](android.md) | blocking, or `suspend` (`AsyncPassboltClient`) |
| .NET (C#) | [.NET](dotnet.md) | blocking, or `Task` (`AsyncPassboltClient`) |
| Go | [Go](go.md) | blocking |
| Ruby | [Ruby](ruby.md) | blocking |
| Swift (iOS) | [Swift](swift.md) | blocking, or `async` (`AsyncPassboltClient`) |

The FFI bindings have two clients with the same methods: `PassboltClient`, whose calls block
(on mobile, call them off the main thread), and `AsyncPassboltClient`, whose calls are awaited
in the language's own way while the SDK's runtime does the network work. Go keeps the blocking
client, its goroutines being the way to wait; Ruby too, since UniFFI does not generate async
code for it yet.

## Concepts

**Session.** `login` takes the server URL, the armored OpenPGP private key of the account and its
passphrase, runs GPGAuth and returns a client holding the session. `logout` ends it, and fails
like any other call when the server cannot be reached or refuses it.

**Pinning.** `fetchServerKey` / `fetch_server_key` returns the server key and its fingerprint,
computed from the key. Show the fingerprint to the user once, save the key, then give it to each
login (`serverPublicKey` / `server_public_key`): the server must then prove it holds the private
key, and another server answering at the same address is refused. The same goes for the shared
metadata key (`metadataKeyFingerprint` / `metadata_key_fingerprint`).

**Resources and views.** A v5 resource keeps its name, username and URIs encrypted. The
*resource views* (`getResourceView`, `listResourceViews`, `get_resource_view`,
`list_resource_views`) decrypt them, and the secret on request, for every resource type: prefer
them to the raw resources. The FFI bindings return a `ResourceView` record: the fields every
resource type shares (`name`, `username`, `uris`, `description`, `password`, `totp`…) are typed,
the others, custom fields and icon among them, are the JSON objects `metadata_json` and
`secret_json`.

**Writes.** `createResource` / `create_resource` takes the fields of the resource, as an object in
JavaScript and as a `NewResource` record in the FFI bindings: `name`, and optionally `username`,
`uris`, `description`, `password`, `totp`, `note`, `pin_code`, `folder_parent_id`, `expired`,
`resource_type`, and the JSON objects `metadata_fields_json` and `secret_fields_json` for the
other fields. The type follows the fields and the server's default version when not given.
`updateResource` / `update_resource` takes only the fields to change (`ResourceChanges` in the FFI
bindings).

**Defaults.** Optional arguments and record fields have defaults in every binding whose language
has them (Kotlin, Swift, Python, Ruby, C#). Go takes option structs for the calls with optional
arguments, whose zero value is the default; Java builds the records with builders
(`NewResourceBuilder`, `ResourceChangesBuilder`, `LoginOptionsBuilder`) and gives every method
argument.

**Sharing.** Permission types are Passbolt's: `1` read, `7` update, `15` owner, `-1` to revoke.

**Errors.** Rust returns `PassboltError`; JavaScript throws an `Error` named `PassboltError`, whose
`code` says what failed (`NOT_FOUND`, `API` with the HTTP `status`…). Python and Ruby raise the
subclasses of `passbolt.PassboltError` and `Passbolt::Error`: `AuthError`, `CryptoError`,
`ApiError` (with the HTTP `status`), `NotFoundError`, `TransportError`, `ConfigError`,
`InvalidArgumentError`. The other FFI bindings raise the `PassboltError` of the language
(`PassboltException` in Kotlin, Java and .NET), whose variants say what failed: `Auth`,
`Crypto`, `Api` (with the HTTP `status`), `NotFound`, `Transport`, `Config`, `InvalidArgument`,
`Other`. Each carries the `reason` of the failure.

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
