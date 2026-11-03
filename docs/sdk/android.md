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

From Maven Central, the AAR brings JNA along. With the AAR file of a release instead, add JNA
yourself:

```kotlin
dependencies {
    implementation(files("libs/passbolt-sdk-android-0.1.1.aar"))
    implementation("net.java.dev.jna:jna:5.14.0@aar")
}
```

Its R8 rules keep the classes JNA reads by reflection: nothing to add to minified apps.

## Log in and list

Everything is in the package `com.passbolt.sdk`. The calls block until the server answers: they
are not `suspend` functions, so run them on `Dispatchers.IO`, never on the main thread.

`PassboltClient` is `AutoCloseable`: `use { }` frees its native memory. `close()` does not end
the server session, `logout()` does.

```kotlin
import com.passbolt.sdk.PassboltClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray

suspend fun resourceNames(serverUrl: String, privateKey: String, passphrase: String): List<String> =
    withContext(Dispatchers.IO) {
        PassboltClient.login(serverUrl, privateKey, passphrase).use { client ->
            try {
                // JSON, the v5 metadata decrypted: one object per resource.
                val views = JSONArray(client.listResourceViews(search = null, withSecrets = false))
                List(views.length()) { index -> views.getJSONObject(index).getString("name") }
            } finally {
                client.logout()
            }
        }
    }
```

The other methods return Kotlin data classes, prefixed with `Ffi`: `FfiResource`, `FfiFolder`,
`FfiUser`… Their optional fields are nullable, their lists `List`, and the numbers that cannot
be negative unsigned (`UInt`, `ULong`).

```kotlin
val folders: List<FfiFolder> = client.listFolders(search = null)
val secret: FfiSecretData = client.decryptResourceSecret(resourceId)
val password: String? = secret.password
```

## Pinning the server, MFA, TLS

`FfiLoginOptions` has no default values: name each argument.

```kotlin
import com.passbolt.sdk.FfiLoginOptions
import com.passbolt.sdk.fetchServerKey

val serverKey = fetchServerKey(serverUrl, tlsSkipVerify = false)   // show serverKey.fingerprint
val options = FfiLoginOptions(
    tlsSkipVerify = false,
    proxy = null,
    mfaTotpToken = null,                                           // the base32 TOTP secret, if any
    serverPublicKey = serverKey.armoredKey,
    metadataKeyFingerprint = null,
    timeoutSeconds = null,
    clientCertificatePem = null,
    clientKeyPem = null,
)
val client = PassboltClient.loginWithConfig(serverUrl, privateKey, passphrase, options)
```

## Errors

`PassboltFfiException` is a sealed class: `PassboltFfiException.Crypto`, `.Api` (with its
`status`), `.Auth`, `.NotFound`, `.Transport`…

```kotlin
try {
    client.getResourceView(id)
} catch (error: PassboltFfiException.NotFound) {
    // gone, or not shared with this user
}
```

The methods are those of the [overview](README.md#what-the-api-covers), in camelCase.
