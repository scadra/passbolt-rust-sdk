---
title: Swift (iOS, macOS)
sidebar_position: 10
---

# Swift (iOS, macOS)

The Swift bindings over an XCFramework for iOS 15 devices (arm64) and simulators (arm64, x86_64),
and macOS 12 (arm64, x86_64). In Xcode, File → Add Package Dependencies, or in `Package.swift`:

```swift
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

## Log in and list

The calls are synchronous and `throws`, not `async`: each one waits for the server. Run them off
the main actor, in a detached task for instance. ARC frees the client; `logout()` ends the server
session.

```swift
import Foundation
import PassboltSDK

func resourceNames(serverUrl: String, privateKey: String, passphrase: String) async throws -> [String] {
    try await Task.detached {
        let client = try PassboltClient.login(
            serverUrl: serverUrl, privateKeyArmored: privateKey, passphrase: passphrase)
        defer { client.logout() }
        // The v5 metadata decrypted: one view per resource.
        return try client.listResourceViews(search: "github").map(\.name)
    }.value
}
```

The methods return structs: `ResourceView`, `Resource`, `Folder`, `User`… Their optional fields
are optionals, and they are `Equatable`, `Hashable`, `Sendable` and `Codable`. A `ResourceView`
holds the fields every resource type shares, decrypted; the others, custom fields and icon among
them, are the JSON objects `metadataJson` and `secretJson`. Arguments and fields left out keep
their default.

```swift
let folders: [Folder] = try client.listFolders()
let view: ResourceView = try client.getResourceView(id: resourceId)
let password: String? = view.password

let created = try client.createResource(
    resource: NewResource(name: "GitHub", username: "ada", password: "…"))
_ = try client.updateResource(id: created.id, changes: ResourceChanges(password: "new"))
// 1 read, 7 update, 15 owner, -1 revokes.
try client.shareResource(id: created.id, permissionType: 7, userIds: [userId])
```

## Pinning the server, MFA, TLS

```swift
let serverKey = try fetchServerKey(serverUrl: serverUrl)
// Show serverKey.fingerprint to the user, save serverKey.armoredKey, then:
let options = LoginOptions(serverPublicKey: serverKey.armoredKey, timeoutSeconds: 30)
let client = try PassboltClient.loginWithConfig(
    serverUrl: serverUrl, privateKeyArmored: privateKey, passphrase: passphrase, options: options)
```

## Errors

Every failing call throws a `PassboltError`: `.Crypto`, `.Api` (with its HTTP `status`),
`.Auth`, `.NotFound`, `.Transport`, `.Config`, `.InvalidArgument`, `.Other`, each with its
`reason`. The cases keep the capital of their Rust names. `localizedDescription` gives the
message, such as `Auth error: …`.

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

The methods are those of the [overview](README.md#what-the-api-covers), in camelCase with
argument labels.
