# JNA + UniFFI generated bindings use reflection / native lookups.
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-dontwarn java.awt.**
-keep class uniffi.keyvora_ffi.** { *; }
