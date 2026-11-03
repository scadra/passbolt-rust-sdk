# JNA finds the native functions and structures by reflection: R8 must keep their names.
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-keep class com.passbolt.sdk.** { *; }
-dontwarn java.awt.**
# The bindings only compile against androidx.annotation (build.gradle.kts): apps may lack it.
-dontwarn androidx.annotation.**
