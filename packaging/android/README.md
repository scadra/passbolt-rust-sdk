# passbolt-sdk for Android

The Kotlin bindings of the Passbolt Rust SDK and its native library for `arm64-v8a`,
`armeabi-v7a`, `x86_64` and `x86`, in one AAR (`passbolt-sdk-android-<version>.aar`), for
Android 7.0 (API 24) and later. The libraries use 16 KB pages, as Android 15 requires.

The bindings call the library through JNA, which an AAR file does not bring along:

```kotlin
dependencies {
    implementation(files("libs/passbolt-sdk-android-0.1.1.aar"))
    implementation("net.java.dev.jna:jna:5.14.0@aar")
}
```

```kotlin
import com.passbolt.sdk.PassboltClient

// Blocking network calls: run them off the main thread.
val client = PassboltClient.login(serverUrl, privateKeyArmored, passphrase)
val resources = client.listResources(null, false, false)
client.logout()
```

Its R8 rules keep the classes JNA reads by reflection. Build it locally from the repository
root, after `scripts/sdk-bindings.sh <lib> bindings kotlin` and
`cargo ndk -o build/android/jniLibs build --release -p passbolt-ffi --lib`:

```sh
gradle -p packaging/android assembleRelease
```
