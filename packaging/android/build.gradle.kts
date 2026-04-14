// The UniFFI Kotlin bindings and the native library of each ABI, as one Android library.
// Inputs, from the repository root by default:
//   -Pbindings=<dir>  Kotlin sources (scripts/sdk-bindings.sh … kotlin), default bindings/kotlin
//   -PjniLibs=<dir>   <abi>/libpassbolt_ffi.so (cargo ndk -o), default build/android/jniLibs
plugins {
    id("com.android.library") version "8.7.3"
    id("org.jetbrains.kotlin.android") version "2.1.0"
}

val repository = rootDir.resolve("../..")
fun input(name: String, default: String) =
    repository.resolve(providers.gradleProperty(name).getOrElse(default))

android {
    namespace = "com.passbolt.sdk"
    compileSdk = 35

    defaultConfig {
        minSdk = 24
        consumerProguardFiles("consumer-rules.pro")
    }

    sourceSets.getByName("main") {
        java.srcDir(input("bindings", "bindings/kotlin"))
        jniLibs.srcDir(input("jniLibs", "build/android/jniLibs"))
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    // The bindings call the library through JNA; its AAR brings libjnidispatch for each ABI.
    api("net.java.dev.jna:jna:5.14.0@aar")
}
