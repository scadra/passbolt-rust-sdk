# JNA finds the native functions and structures by reflection: R8 must keep their names.
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-keep class com.passbolt.sdk.** { *; }
-dontwarn java.awt.**
