---
title: Swift (iOS)
sidebar_position: 10
---

# Swift (iOS)

The Swift bindings over an XCFramework for devices (arm64) and simulators (arm64, x86_64), iOS 15
or later. In Xcode, File → Add Package Dependencies, or in `Package.swift`:

```swift
.package(url: "https://github.com/scadra/passbolt-sdk-swift", from: "0.1.0")
```

then the product `PassboltSDK`. The `PassboltSDK-ios-<version>.zip` of each release is the same
package with the XCFramework inside, to add as a local package.

## Log in and list

The calls block: run them off the main thread.

```swift
import Foundation
import PassboltSDK

func resourceNames(serverUrl: String, privateKey: String, passphrase: String) async throws -> [String] {
    try await Task.detached {
        let client = try PassboltClient.login(
            serverUrl: serverUrl, privateKeyArmored: privateKey, passphrase: passphrase)
        defer { client.logout() }
        let views = try JSONSerialization.jsonObject(
            with: Data(try client.listResourceViews(search: nil, withSecrets: false).utf8)
        ) as? [[String: Any]] ?? []
        return views.compactMap { $0["name"] as? String }
    }.value
}
```

## Pinning the server and errors

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
