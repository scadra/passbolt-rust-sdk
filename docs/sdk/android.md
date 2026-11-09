---
title: Android (Kotlin)
sidebar_position: 6
---

# Android (Kotlin)

An AAR with the Kotlin bindings and the native library for `arm64-v8a`, `armeabi-v7a`, `x86_64`
and `x86`, for Android 7.0 (API 24) and later. The libraries use 16 KB pages, as Android 15
requires.

```kotlin
dependencies {
    implementation("io.github.scadra:passbolt-sdk-android:0.1.1")
}
```

From Maven Central, the AAR brings JNA and kotlinx-coroutines along. With the AAR file of a
release instead, add them yourself:

```kotlin
dependencies {
    implementation(files("libs/passbolt-sdk-android-0.1.1.aar"))
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
}
```

Its R8 rules keep the classes JNA reads by reflection: nothing to add to minified apps.

## Log in and list

Everything is in the package `com.passbolt.sdk`. `AsyncPassboltClient` has `suspend`
functions: call them from any coroutine, the main one included, the SDK's own threads wait for
the server.

`AsyncPassboltClient` is `AutoCloseable`: `use { }` frees its native memory. `close()` does not
end the server session, `logout()` does.

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

`PassboltClient` has the same methods, blocking until the server answers: run them on
`Dispatchers.IO` or a thread of your own, never on the main thread.

The methods return Kotlin data classes: `ResourceView`, `Resource`, `Folder`, `User`… Their
optional fields are nullable, their lists `List`, and the numbers that cannot be negative
unsigned (`UInt`, `ULong`). A `ResourceView` holds the fields every resource type shares,
decrypted; the others, custom fields and icon among them, are the JSON objects `metadataJson`
and `secretJson`. Arguments and fields left out keep their default.

```kotlin
val folders: List<Folder> = client.listFolders()
val view: ResourceView = client.getResourceView(resourceId)
val password: String? = view.password

val created = client.createResource(NewResource(name = "GitHub", username = "ada", password = "…"))
client.updateResource(created.id, ResourceChanges(password = "new"))
// 1 read, 7 update, 15 owner, -1 revokes.
client.shareResource(created.id, permissionType = 7, userIds = listOf(userId))
```

## Pinning the server, MFA, TLS

```kotlin
import com.passbolt.sdk.LoginOptions
import com.passbolt.sdk.fetchServerKey

val serverKey = fetchServerKey(serverUrl)   // show serverKey.fingerprint to the user
val options = LoginOptions(
    serverPublicKey = serverKey.armoredKey,
    mfaTotpToken = totpSecret,               // the base32 TOTP secret, for an account with TOTP
)
val client = PassboltClient.loginWithConfig(serverUrl, privateKey, passphrase, options)
```

## Generating passwords

As the browser extension: passwords from character sets, passphrases of words of the EFF list,
PIN codes, from the password policies of the organization or settings of your own. The fields
left out keep the defaults of Passbolt.

```kotlin
val policies = client.getPasswordPolicies() // the organization's: generator and settings
val secret = generateSecret(policies)

val password = generatePassword(PasswordGeneratorSettings(length = 24u))
val passphrase = generatePassphrase(
    PassphraseGeneratorSettings(words = 6u, wordCase = WordCase.CAMELCASE))
val pinCode = generatePinCode(6u)

val strength: Strength = secretStrength(password) // VERY_STRONG, as the extension shows it
```

They are functions of the package `com.passbolt.sdk`, and need no session; without one,
`defaultPasswordPolicies()` gives the defaults of Passbolt.

## Errors

Every failing call throws a `PassboltException`, a sealed class: `PassboltException.Crypto`,
`.Api` (with its HTTP `status`), `.Auth`, `.NotFound`, `.Transport`, `.Config`,
`.InvalidArgument`, `.Other`. Each case has the explanation in `reason`; `message` reads
`reason=…`.

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

The methods are those of the [overview](README.md#what-the-api-covers), in camelCase.
