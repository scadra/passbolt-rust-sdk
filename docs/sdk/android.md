---
title: Android (Kotlin)
sidebar_position: 6
---

# Android (Kotlin)

Use the `passbolt-sdk-android` AAR to log in to Passbolt and read, write and share secrets from
Kotlin, with `suspend` functions or blocking calls.

## Installation

The package is on Maven Central as `io.github.scadra:passbolt-sdk-android`: an AAR with the Kotlin
bindings and the native library for `arm64-v8a`, `armeabi-v7a`, `x86_64` and `x86`. It needs
Android 7.0 (API 24) or later. The libraries use 16 KB pages, as Android 15 requires.

```kotlin title="build.gradle.kts"
dependencies {
    implementation("io.github.scadra:passbolt-sdk-android:0.1.1")
}
```

From Maven Central, the AAR brings JNA and kotlinx-coroutines along. With the AAR file of a
release instead, add them yourself:

```kotlin title="build.gradle.kts"
dependencies {
    implementation(files("libs/passbolt-sdk-android-0.1.1.aar"))
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
}
```

Its R8 rules keep the classes JNA reads by reflection: there is nothing to add to minified apps.

## Initialize

Everything is in the package `com.passbolt.sdk`. `AsyncPassboltClient` has `suspend` functions:
call them from any coroutine, the main one included, while the SDK's own threads wait for the
server.

`AsyncPassboltClient` is `AutoCloseable`: `use { }` frees its native memory. `close()` does not
end the server session; `logout()` does.

```kotlin
import com.passbolt.sdk.AsyncPassboltClient

suspend fun resourceNames(serverUrl: String, privateKey: String, passphrase: String): List<String> =
    AsyncPassboltClient.login(serverUrl, privateKey, passphrase).use { client ->
        try {
            // The v5 metadata decrypted: one view per resource.
            client.listResourceViews(search = "github").map { view -> view.name }
        } finally {
            client.logout()
        }
    }
```

:::caution
`PassboltClient` has the same methods, blocking until the server answers: run them on
`Dispatchers.IO` or a thread of your own, never on the main thread.
:::

## Login options

`loginWithConfig` takes a `LoginOptions`. Its fields are optional and keep their default when you
leave them out.

| Field | Type | Description |
|---|---|---|
| `serverPublicKey` | `String?` | The armored server key pinned with `fetchServerKey`. |
| `metadataKeyFingerprint` | `String?` | The pinned fingerprint of the shared metadata key. |
| `mfaTotpToken` | `String?` | The base32 TOTP secret, for an account with TOTP. |
| `timeoutSeconds` | `ULong?` | Seconds a request may take. Default: 60; `0` waits forever. |
| `proxy` | `String?` | The proxy URL. |
| `tlsSkipVerify` | `Boolean` | Skip the certificate check. Default: `false`. |
| `clientCertificatePem`, `clientKeyPem` | `String?` | The PEM certificate and key, for mTLS. |

### Pin the server key and answer MFA

```kotlin
import com.passbolt.sdk.LoginOptions
import com.passbolt.sdk.PassboltClient
import com.passbolt.sdk.fetchServerKey

val serverKey = fetchServerKey(serverUrl)   // show serverKey.fingerprint to the user
val options = LoginOptions(
    serverPublicKey = serverKey.armoredKey,
    mfaTotpToken = totpSecret,               // the base32 TOTP secret, for an account with TOTP
)
val client = PassboltClient.loginWithConfig(serverUrl, privateKey, passphrase, options)
```

## Read resources

The methods return Kotlin data classes: `ResourceView`, `Resource`, `Folder`, `User`… Their
optional fields are nullable, their lists `List`, and the numbers that cannot be negative
unsigned (`UInt`, `ULong`).

A `ResourceView` holds the fields every resource type shares, decrypted; the others, custom
fields and icon among them, are the JSON objects `metadataJson` and `secretJson`.

### Read a password and list your folders

```kotlin
val folders: List<Folder> = client.listFolders()
val view: ResourceView = client.getResourceView(resourceId)
val password: String? = view.password
```

## Create and share resources

`createResource` takes a `NewResource`, `updateResource` a `ResourceChanges`. Arguments and fields
you leave out keep their default.

### Create, update and share a resource

```kotlin
val created = client.createResource(NewResource(name = "GitHub", username = "ada", password = "…"))
client.updateResource(created.id, ResourceChanges(password = "new"))
// 1 read, 7 update, 15 owner, -1 revokes.
client.shareResource(created.id, permissionType = 7, userIds = listOf(userId))
```

## Generate a password

Generate passwords from character sets, passphrases of words of the EFF list, and PIN codes, as
the browser extension does. Start from the password policies of the organization or from settings
of your own: the fields you leave out keep the defaults of Passbolt.

The generator functions are in the package `com.passbolt.sdk` and need no session. Without one,
`defaultPasswordPolicies()` gives the defaults of Passbolt.

### Generate secrets and rate them

```kotlin
val policies = client.getPasswordPolicies() // the organization's: generator and settings
val secret = generateSecret(policies)

val password = generatePassword(PasswordGeneratorSettings(length = 24u))
val passphrase = generatePassphrase(
    PassphraseGeneratorSettings(words = 6u, wordCase = WordCase.CAMELCASE))
val pinCode = generatePinCode(6u)

val strength: Strength = secretStrength(password) // VERY_STRONG, as the extension shows it
```

## Handle errors

Every failing call throws a `PassboltException`, a sealed class: `PassboltException.Crypto`,
`.Api` (with its HTTP `status`), `.Auth`, `.NotFound`, `.Transport`, `.Config`,
`.InvalidArgument`, `.Other`. Each case has the explanation in `reason`; `message` reads
`reason=…`.

### Catch a missing resource and an API error

```kotlin
import com.passbolt.sdk.PassboltException

try {
    client.getResourceView(id)
} catch (error: PassboltException.NotFound) {
    // gone, or not shared with this user
} catch (error: PassboltException.Api) {
    Log.w("passbolt", "HTTP ${error.status}: ${error.reason}")
}
```

A `when` over a caught `PassboltException` lists every case, without `else`.

## Method names

The methods are those of the [overview](README.md#what-the-api-covers), in camelCase.

## Related

- [Overview](README.md): the concepts shared by every language.
- [API reference](api.md): every method, function and record.
- [Java](java.md): the same API for the JVM.
- [Upgrading](upgrading.md): the breaking changes since the 0.1.1 packages.
