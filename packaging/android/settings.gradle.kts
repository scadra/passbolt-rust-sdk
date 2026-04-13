// Passbolt SDK for Android: `gradle -p packaging/android assembleRelease` builds the AAR.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "passbolt-sdk"
