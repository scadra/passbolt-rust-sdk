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

/// The fields of `listResourceViews` this app reads; the JSON has more.
struct ResourceView: Decodable {
    let id: String
    let name: String
    let username: String
}

func resourceNames(serverUrl: String, privateKey: String, passphrase: String) async throws -> [String] {
    try await Task.detached {
        let client = try PassboltClient.login(
            serverUrl: serverUrl, privateKeyArmored: privateKey, passphrase: passphrase)
        defer { client.logout() }
        // JSON, the v5 metadata decrypted: one object per resource.
        let json = try client.listResourceViews(search: nil, withSecrets: false)
        return try JSONDecoder().decode([ResourceView].self, from: Data(json.utf8)).map(\.name)
    }.value
}
```

The other methods return structs, prefixed with `Ffi`: `FfiResource`, `FfiFolder`, `FfiUser`…
Their optional fields are optionals, and they are `Equatable`, `Hashable`, `Sendable` and
`Codable`.

```swift
let folders: [FfiFolder] = try client.listFolders(search: nil)
let secret: FfiSecretData = try client.decryptResourceSecret(resourceId: resourceId)
let password: String? = secret.password
```


```swift
let serverKey = try fetchServerKey(serverUrl: serverUrl, tlsSkipVerify: false)
// Show serverKey.fingerprint to the user, save serverKey.armoredKey, then:
let options = FfiLoginOptions(
    tlsSkipVerify: false, proxy: nil, mfaTotpToken: nil,
    serverPublicKey: serverKey.armoredKey, metadataKeyFingerprint: nil,
    timeoutSeconds: nil, clientCertificatePem: nil, clientKeyPem: nil)

do {
    let client = try PassboltClient.loginWithConfig(
        serverUrl: serverUrl, privateKeyArmored: privateKey, passphrase: passphrase, options: options)
    _ = client
} catch PassboltFfiError.Auth(let reason) {
    print("login refused: \(reason)")
}
```

The methods are those of the [overview](README.md#what-the-api-covers), in camelCase with
argument labels.
