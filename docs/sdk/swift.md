---
title: Swift (iOS, macOS)
sidebar_position: 10
---

# Swift (iOS, macOS)

Use the `PassboltSDK` package to log in to Passbolt and read, write and share secrets from Swift,
with `async` methods or blocking calls.

## Installation

The package is `https://github.com/scadra/passbolt-sdk-swift`: the Swift bindings over an
XCFramework. It needs iOS 15 (devices arm64, simulators arm64 and x86_64) or macOS 12 (arm64,
x86_64).

In Xcode, choose **File** > **Add Package Dependencies** and enter the package URL. Or add it to
`Package.swift`:

```swift title="Package.swift"
dependencies: [
    .package(url: "https://github.com/scadra/passbolt-sdk-swift", from: "0.1.1"),
],
targets: [
    .target(name: "MyApp", dependencies: [
        .product(name: "PassboltSDK", package: "passbolt-sdk-swift"),
    ]),
]
```

The `PassboltSDK-<version>.zip` of each release is the same package with the XCFramework inside,
to add as a local package.

## Initialize

The methods of `AsyncPassboltClient` are `async throws`: await them from any task, the main actor
included, while the SDK's own threads wait for the server. ARC frees the client; `logout()` ends
the server session, and throws like the other calls.

```swift
import PassboltSDK

func resourceNames(serverUrl: String, privateKey: String, passphrase: String) async throws -> [String] {
    let client = try await AsyncPassboltClient.login(
        serverUrl: serverUrl, privateKeyArmored: privateKey, passphrase: passphrase)
    // The v5 metadata decrypted: one view per resource.
    let names = try await client.listResourceViews(search: "github").map(\.name)
    try await client.logout()
    return names
}
```

:::caution
`PassboltClient` has the same methods, synchronous: each one blocks until the server answers, so
keep them off the main actor.
:::

## Login options

`loginWithConfig` takes a `LoginOptions`. Its fields are optional and keep their default when you
leave them out.

| Field | Type | Description |
|---|---|---|
| `serverPublicKey` | `String?` | The armored server key pinned with `fetchServerKey`. |
| `metadataKeyFingerprint` | `String?` | The pinned fingerprint of the shared metadata key. |
| `mfaTotpToken` | `String?` | The base32 TOTP secret, for an account with TOTP. |
| `timeoutSeconds` | `UInt64?` | Seconds a request may take. Default: 60; `0` waits forever. |
| `proxy` | `String?` | The proxy URL. |
| `tlsSkipVerify` | `Bool` | Skip the certificate check. Default: `false`. |
| `clientCertificatePem`, `clientKeyPem` | `String?` | The PEM certificate and key, for mTLS. |

### Pin the server key

```swift
let serverKey = try fetchServerKey(serverUrl: serverUrl)
// Show serverKey.fingerprint to the user, save serverKey.armoredKey, then:
let options = LoginOptions(serverPublicKey: serverKey.armoredKey, timeoutSeconds: 30)
let client = try PassboltClient.loginWithConfig(
    serverUrl: serverUrl, privateKeyArmored: privateKey, passphrase: passphrase, options: options)
```

## Read resources

The methods return structs: `ResourceView`, `Resource`, `Folder`, `User`… Their optional fields
are optionals, and they are `Equatable`, `Hashable`, `Sendable` and `Codable`.

A `ResourceView` holds the fields every resource type shares, decrypted; the others, custom
fields and icon among them, are the JSON objects `metadataJson` and `secretJson`.

### Read a password and list your folders

```swift
let folders: [Folder] = try client.listFolders()
let view: ResourceView = try client.getResourceView(id: resourceId)
let password: String? = view.password
```

## Create and share resources

`createResource` takes a `NewResource`, `updateResource` a `ResourceChanges`. Arguments and fields
you leave out keep their default.

### Create, update and share a resource

```swift
let created = try client.createResource(
    resource: NewResource(name: "GitHub", username: "ada", password: "…"))
_ = try client.updateResource(id: created.id, changes: ResourceChanges(password: "new"))
// 1 read, 7 update, 15 owner, -1 revokes.
try client.shareResource(id: created.id, permissionType: 7, userIds: [userId])
```

## Generate a password

Generate passwords from character sets, passphrases of words of the EFF list, and PIN codes, as
the browser extension does. Start from the password policies of the organization or from settings
of your own: the fields you leave out keep the defaults of Passbolt.

Without a session, `defaultPasswordPolicies()` gives the defaults of Passbolt.

### Generate secrets and rate them

```swift
let policies = try client.getPasswordPolicies() // the organization's: generator and settings
let secret = try generateSecret(policies: policies)

let password = try generatePassword(settings: PasswordGeneratorSettings(length: 24))
let passphrase = try generatePassphrase(
    settings: PassphraseGeneratorSettings(words: 6, wordCase: .camelcase))
let pinCode = generatePinCode(length: 6)

let strength = secretStrength(secret: password) // .veryStrong, as the extension shows it
```

## Handle errors

Every failing call throws a `PassboltError`: `.Crypto`, `.Api` (with its HTTP `status`),
`.Auth`, `.NotFound`, `.Transport`, `.Config`, `.InvalidArgument`, `.Other`, each with its
`reason`. The cases keep the capital of their Rust names. `localizedDescription` gives the
message, such as `Auth error: …`.

### Catch a missing resource and an API error

```swift
do {
    _ = try client.getResourceView(id: id)
} catch PassboltError.NotFound {
    // gone, or not shared with this user
} catch PassboltError.Api(let status, let reason) {
    print("HTTP \(status): \(reason)")
} catch {
    print(error.localizedDescription)
}
```

## Method names

The methods are those of the [overview](README.md#what-the-api-covers), in camelCase with
argument labels.

## Related

- [Overview](README.md): the concepts shared by every language.
- [API reference](api.md): every method, function and record.
- [Upgrading](upgrading.md): the breaking changes since the 0.1.1 packages.
