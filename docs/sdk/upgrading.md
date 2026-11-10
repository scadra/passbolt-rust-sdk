---
title: Upgrading
sidebar_position: 12
---

# Upgrading

The breaking changes since the 0.1.1 packages, the version the language pages install, in each
binding and in the CLI. They are the changes of the `[Unreleased]` section of `CHANGELOG.md`,
made after the tag `v0.1.2`. Each section shows the code before and after.

| Binding | Breaking changes |
|---|---|
| Every FFI binding | Type names, resource views and writes, share argument order, `login_with_options`, `logout` |
| Python | Package `passbolt` instead of `passbolt_ffi` |
| Ruby | `require "passbolt"` and `Passbolt::` names |
| Go | Option structs, Go initialisms, `Close` |
| Java | Records with accessors, builders |
| Android | kotlinx-coroutines dependency |
| Swift | Release asset names |
| .NET | Public types, `PassboltFfi` |
| JavaScript | Options objects, error codes, `checkPasswordPwned`, `logout` |
| Rust | `logout` returns a `Result` |
| CLI | None |

## Every FFI binding

### Types without the `Ffi` prefix

The records and the error lose their `Ffi` prefix:

| Before | After |
|---|---|
| `FfiLoginOptions`, `FfiServerKey` | `LoginOptions`, `ServerKey` |
| `FfiResource`, `FfiFolder`, `FfiUser`, `FfiGroup`, `FfiPermission`… | `Resource`, `Folder`, `User`, `Group`, `Permission`… |
| `PassboltFfiError` (Python, Ruby, Swift, Go) | `PassboltError` |
| `PassboltFfiException` (Kotlin, Java, .NET) | `PassboltException` |

```kotlin
// Before
val options = FfiLoginOptions(
    tlsSkipVerify = false, proxy = null, mfaTotpToken = null,
    serverPublicKey = serverKey.armoredKey, metadataKeyFingerprint = null,
    timeoutSeconds = null, clientCertificatePem = null, clientKeyPem = null,
)
try { client.getResourceView(id) } catch (error: PassboltFfiException.NotFound) { }

// After
val options = LoginOptions(serverPublicKey = serverKey.armoredKey)
try { client.getResourceView(id) } catch (error: PassboltException.NotFound) { }
```

### Resource views are records

`get_resource_view` and `list_resource_views` returned JSON text; they return a `ResourceView`
and a list of them. The fields every resource type shares are typed (`name`, `username`, `uris`,
`description`, `password`, `totp`…); the others are the JSON objects `metadata_json` and
`secret_json`. See [ResourceView](api.md#resourceview).

```swift
// Before
let json = try client.listResourceViews(search: nil, withSecrets: false)
let views = try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [[String: Any]] ?? []
let names = views.compactMap { $0["name"] as? String }

// After
let names = try client.listResourceViews().map(\.name)
```

### Resources are written from records

`create_resource` took the JSON text of the new resource, `update_resource` the JSON text of the
changes. They take a [`NewResource`](api.md#newresource) and a
[`ResourceChanges`](api.md#resourcechanges). A JSON `"expired": null` cleared the expiry; it is
`clear_expiry`. Fields without a typed field go in `metadata_fields_json` and
`secret_fields_json`.

```python
# Before
created = client.create_resource(json.dumps({"name": "GitHub", "username": "ada", "password": "…"}))
client.update_resource(created.id, json.dumps({"password": "new", "expired": None}))

# After
created = client.create_resource(passbolt.NewResource(name="GitHub", username="ada", password="…"))
client.update_resource(created.id, passbolt.ResourceChanges(password="new", clear_expiry=True))
```

### Defaults

Optional arguments and record fields have defaults, in the languages that have default arguments
(Kotlin, Swift, Python, Ruby, C#): `list_resources()`, `list_folders()`, `create_folder(name)`,
`fetch_server_key(url)`, `LoginOptions(server_public_key=…)`. The defaults of each method are in
the [API reference](api.md#methods). Calls that give every argument keep working, except
`share_resource` and `share_folder`.

### `share_resource` and `share_folder`: the permission type first

The permission type comes before the users and groups, which are empty by default.

```kotlin
// Before
client.shareResource(id, listOf(userId), emptyList(), 7)
client.shareFolder(id, listOf(userId), emptyList(), 7, true)

// After
client.shareResource(id, permissionType = 7, userIds = listOf(userId))
client.shareFolder(id, permissionType = 7, userIds = listOf(userId), withContent = true)
```

### `login_with_options` is gone

`login_with_config` takes its options, in a `LoginOptions`:

```swift
// Before
let client = try PassboltClient.loginWithOptions(
    serverUrl: url, privateKeyArmored: key, passphrase: passphrase,
    tlsSkipVerify: false, proxy: proxy, mfaTotpToken: totpSecret)

// After
let client = try PassboltClient.loginWithConfig(
    serverUrl: url, privateKeyArmored: key, passphrase: passphrase,
    options: LoginOptions(proxy: proxy, mfaTotpToken: totpSecret))
```

### `logout` fails like any other call

`logout` ignored the answer of the server. It returns its error: a server that cannot be reached
or refuses the logout raises `PassboltError` (`PassboltException`), and Swift's `logout()` is
`throws`. The server session then ends when it expires.

```kotlin
// Before: logout() never threw
client.logout()

// After
try {
    client.logout()
} catch (error: PassboltException) {
    Log.w("passbolt", "logout failed: ${error.message}")
}
```

### New: the async client

`AsyncPassboltClient` has the methods of `PassboltClient`, awaited: a coroutine in Python, a
`suspend` function in Kotlin, `async` in Swift, a `Task` in C#, a `CompletableFuture` in Java. Go
and Ruby keep the blocking client. Nothing changes for the code that uses `PassboltClient`. See
[The async client](api.md#the-async-client).

## Python

The package is imported as `passbolt`, over the generated module `passbolt._ffi`. `passbolt.Client`
logs in with keyword options and logs out at the end of a `with` block; the errors are
subclasses of `passbolt.PassboltError`.

```python
# Before
import passbolt_ffi

options = passbolt_ffi.FfiLoginOptions(
    tls_skip_verify=False, proxy=None, mfa_totp_token=None,
    server_public_key=server_key, metadata_key_fingerprint=None,
    timeout_seconds=None, client_certificate_pem=None, client_key_pem=None,
)
client = passbolt_ffi.PassboltClient.login_with_config(url, private_key, passphrase, options)
try:
    views = json.loads(client.list_resource_views("github", False))
    client.share_resource(resource_id, [user_id], [], 7)
except passbolt_ffi.PassboltFfiError.Api as error:
    print(error.status)
finally:
    client.logout()

# After
import passbolt

with passbolt.Client.login(url, private_key, passphrase, server_public_key=server_key) as client:
    try:
        views = client.list_resource_views("github")
        client.share_resource(resource_id, passbolt.PermissionType.UPDATE, user_ids=[user_id])
    except passbolt.ApiError as error:
        print(error.status)
```

## Ruby

`require "passbolt"` gives `Passbolt::Client`, with keyword options, flags as keywords and a block
that logs out; the errors are `Passbolt::Error`. `require "passbolt_sdk"` still loads the gem, and
the generated module stays `PassboltFfi`, with the new type names.

```ruby
# Before
require "passbolt_sdk"

client = PassboltFfi::PassboltClient.login(url, private_key, passphrase)
begin
  views = JSON.parse(client.list_resource_views("github", false))
  client.share_resource(resource_id, [user_id], [], 7)
rescue PassboltFfi::PassboltFfiError::NotFound
  puts "gone"
ensure
  client.logout
end

# After
require "passbolt"

Passbolt::Client.login(url, private_key, passphrase) do |client|
  views = client.list_resource_views("github")
  client.share_resource(resource_id, permission_type: Passbolt::PermissionType::UPDATE, user_ids: [user_id])
rescue Passbolt::NotFoundError
  puts "gone"
end
```

## Go

- The generated package was `passbolt_ffi`; it is `passbolt`. With the import name `passbolt`,
  nothing changes.
- Go initialisms: `ID`, `URL`, `URI`, `JSON`, `API`, `TLS`, `HTTP` are capitals (`view.ID`,
  `GetResourcesByIDs`, `BaseURL()`, `PassboltErrorAPI`, `LoginOptions.TLSSkipVerify`).
- The calls with optional arguments take an option struct instead of their arguments:
  `ListResources`, `ListResourceViews`, `ListFolders`, `ListUsers`, `UpdateGroup`, `UpdateUser`,
  `ShareResource`, `ShareFolder`. See [Go](go.md#options).
- `Close` logs out and releases the client, and returns the error of the logout. The generated
  plumbing (`FfiConverter…`, `RustBuffer…`) is unexported.
- The error is `*passbolt.PassboltError`, its variants `*PassboltErrorAuth`,
  `*PassboltErrorAPI`, `*PassboltErrorNotFound`…

```go
// Before
defer client.Destroy()
defer client.Logout()
search := "github"
viewsJSON, err := client.ListResourceViews(&search, false)
// … json.Unmarshal into []map[string]any, then view["id"]
err = client.ShareResource(resourceID, []string{userID}, []string{}, 7)

// After
defer client.Close()
views, err := client.ListResourceViews(&passbolt.ResourceViewListOptions{Search: "github"})
// … views[0].ID, views[0].Name
err = client.ShareResource(resourceID, passbolt.Share{
	Permission: passbolt.PermissionUpdate,
	UserIDs:    []string{userID},
})
```

`passbolt.Call` and `passbolt.Run` are new: they stop waiting for a call when a
`context.Context` ends.

## Java

The records are Java records, read with their accessors (`created.id()`, `view.name()`). The
records you write have builders that start from their
defaults: `LoginOptionsBuilder`, `NewResourceBuilder`, `ResourceChangesBuilder`,
`TotpDataBuilder`. Java has no default arguments: the methods still take every argument.

```java
// Before
FfiLoginOptions options = new FfiLoginOptions(
    false, null, null, serverPublicKey, null, null, null, null);
PassboltClient client = PassboltClient.loginWithConfig(url, privateKey, passphrase, options);
String viewsJson = client.listResourceViews("github", false);
client.createResource("{\"name\": \"GitHub\", \"password\": \"…\"}");
client.shareResource(resourceId, List.of(userId), List.of(), 7);

// After
LoginOptions options = new LoginOptionsBuilder().serverPublicKey(serverPublicKey).build();
PassboltClient client = PassboltClient.loginWithConfig(url, privateKey, passphrase, options);
List<ResourceView> views = client.listResourceViews("github", false);
client.createResource(new NewResourceBuilder("GitHub").password("…").build());
client.shareResource(resourceId, 7, List.of(userId), List.of());
```

The jar declares the automatic module name `com.passbolt.sdk`.

## Android

The AAR depends on `org.jetbrains.kotlinx:kotlinx-coroutines-core`, for the `suspend` functions
of `AsyncPassboltClient`. Maven Central brings it along; with the AAR file of a release, add it:

```kotlin
dependencies {
    implementation(files("libs/passbolt-sdk-android-<version>.aar"))
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
}
```

The changes of [every FFI binding](#every-ffi-binding) apply: `LoginOptions`,
`PassboltException`, `ResourceView`, `NewResource`, `ResourceChanges`, and the permission type
first in `shareResource` and `shareFolder`.

## Swift

The module is still `import PassboltSDK`, over a C module renamed `PassboltSDKFFI`. The package
also builds for macOS 12. The release assets are `PassboltSDK-<version>.zip` (it was
`PassboltSDK-ios-<version>.zip`) and `PassboltSDKFFI.xcframework.zip`. The records are `Codable`,
and the errors describe themselves with the Rust messages (`localizedDescription`).

```swift
// Before
do {
    let client = try PassboltClient.login(
        serverUrl: url, privateKeyArmored: key, passphrase: passphrase)
    defer { client.logout() }
} catch PassboltFfiError.Auth(let reason) {
    print("login refused: \(reason)")
}

// After
do {
    let client = try PassboltClient.login(
        serverUrl: url, privateKeyArmored: key, passphrase: passphrase)
    defer { try? client.logout() }  // logout() throws
} catch PassboltError.Auth(let reason) {
    print("login refused: \(reason)")
}
```

## .NET

The types of the 0.1.1 package were all `internal`, generated with the default access of
uniffi-bindgen-cs: code outside the package could not call them. They are public. The stateless
functions are static methods of `PassboltFfi` (`PassboltFfi.FetchServerKey`,
`PassboltFfi.GetKeyFingerprint`), the exception is `PassboltException`, the records are C#
records, and the arguments with a default can be left out, by name:

```csharp
using var client = PassboltClient.Login("https://passbolt.example.com", privateKey, passphrase);
foreach (var view in client.ListResourceViews(search: "github"))
{
    Console.WriteLine(view.name);
}
client.ShareResource(resourceId, permissionType: 7, userIds: [userId]);
client.Logout();
```

The package holds the native libraries under `runtimes/<rid>/native` once, with the XML
documentation.

## JavaScript

- The methods with optional arguments take an options object, with camelCase keys.
- Errors are `Error`s named `PassboltError` with a `code` (`NOT_FOUND`, `API` with the HTTP
  `status`, `SESSION_EXPIRED`…); `isPassboltError` narrows an unknown error to it. They were
  plain `Error`s with the message of the SDK.
- `checkPasswordPwned` returns a `number`; it was a `bigint`.
- `logout` rejects with the error of the server; it ignored it.
- Each session has its own `csrfTokenProvider`.
- Node.js 20.19 or later.

| Before | After |
|---|---|
| `listResources(search, favoritesOnly, ownedByMe)` | `listResources({ search, favoritesOnly, ownedByMe })` |
| `listResourceViews(search, withSecrets)` | `listResourceViews({ search, withSecrets })` |
| `listFolders(search)` | `listFolders({ search })` |
| `listUsers(search, groupId, adminOnly)` | `listUsers({ search, groupId, adminOnly })` |
| `shareResource(id, userIds, groupIds, permissionType)` | `shareResource(id, { userIds, groupIds, permissionType })` |
| `shareFolder(id, userIds, groupIds, permissionType, withContent)` | `shareFolder(id, { userIds, groupIds, permissionType, withContent })` |
| `createUser(username, firstName, lastName, role)` | `createUser({ username, firstName, lastName, role })` |
| `updateUser(id, firstName, lastName, role)` | `updateUser(id, { firstName, lastName, role })` |
| `createGroup(name, memberIds, managerIds)` | `createGroup({ name, memberIds, managerIds })` |
| `updateGroup(id, name, addMemberIds, addManagerIds, removeMemberIds)` | `updateGroup(id, { name, addMemberIds, addManagerIds, removeMemberIds })` |

```ts
// Before
const views = await session.listResourceViews("github", false);
await session.shareResource(id, [userId], [], 7);
try {
  await session.getResource(id);
} catch (error) {
  console.error((error as Error).message);
}

// After
const views = await session.listResourceViews({ search: "github" });
await session.shareResource(id, { userIds: [userId], permissionType: 7 });
try {
  await session.getResource(id);
} catch (error) {
  if (isPassboltError(error) && error.code === "NOT_FOUND") console.log("No such resource");
  else throw error;
}
```

The full list of methods and codes is on the [JavaScript](javascript.md) page.

## Rust

`PassboltSdk::logout` returns `Result<(), PassboltError>`: an error means the server may still
hold the session, until it expires.

```rust
// Before
client.logout().await;

// After
client.logout().await?;
```

## CLI

No breaking change: the commands, flags, environment variables and outputs stay the same. A
failed logout at the end of a command prints `Warning: failed to log out: …` on stderr and the
command keeps its result. New: `passbolt tui`, `passbolt generate`, and `--generate` on
`create resource` and `update resource`.
