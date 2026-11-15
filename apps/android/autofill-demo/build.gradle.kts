// Test-only app with a login form, used to exercise Keyvora's AutofillService on an emulator/device.
// It is never published and has no dependencies.
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "com.keyvora.autofilldemo"
    compileSdk = 35
    defaultConfig {
        applicationId = "com.keyvora.autofilldemo"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions { jvmTarget.set(JvmTarget.JVM_17) }
}
