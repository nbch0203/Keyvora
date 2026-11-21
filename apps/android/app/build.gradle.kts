import java.util.Properties
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

// The Rust core (UniFFI Kotlin bindings + libkeyvora_ffi.so) is generated outside Gradle (see README.md).
// When the generated bindings exist the `uniffi` source set is compiled; otherwise the `nocore` one, whose
// CoreBridge throws CoreException("CORE_NOT_BUILT"). Both define com.keyvora.app.core.CoreBridgeFactory.
val coreGeneratedDir = file("../core-generated")
// `-Pkeyvora.forceNoCore=true` builds the no-core variant even when the bindings exist (checks both states in CI).
val forceNoCore = (project.findProperty("keyvora.forceNoCore") ?: "false").toString() == "true"
val coreAvailable = !forceNoCore && file("../core-generated/uniffi/keyvora_ffi/keyvora_ffi.kt").exists()
val testVectors = file("../../../packages/shared-models/test-vectors/vault-v1.json")
// Host build of the core (libkeyvora_ffi.so / keyvora_ffi.dll) for JVM unit tests (CoreVectorsTest).
val hostCoreDir = file("../core-generated/host")
// Release signing key: apps/android/keystore.properties (git-ignored, never committed) with storeFile, storePassword,
// keyAlias and keyPassword. Without it `assembleRelease` produces an unsigned APK (README: «Compilar para uso real»).
val keystoreProps = Properties().apply {
    val f = rootProject.file("keystore.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}

android {
    namespace = "com.keyvora.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.keyvora.app"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
        buildConfigField("boolean", "CORE_AVAILABLE", coreAvailable.toString())
        // Only the ABIs libkeyvora_ffi.so is built for (JNA's AAR also ships armeabi/mips, which would break the core).
        ndk { abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86", "x86_64") }
    }

    signingConfigs {
        if (keystoreProps.getProperty("storeFile") != null) {
            create("release") {
                storeFile = rootProject.file(keystoreProps.getProperty("storeFile"))
                storePassword = keystoreProps.getProperty("storePassword")
                keyAlias = keystoreProps.getProperty("keyAlias")
                keyPassword = keystoreProps.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        debug {
            // `-Pkeyvora.allowScreenshots=true` (emulator UI review only): drops FLAG_SECURE so screens can be
            // captured. Debug builds only: release is always false, whatever the property (AUDIT SUP-8).
            val allowScreenshots = (project.findProperty("keyvora.allowScreenshots") ?: "false").toString() == "true"
            buildConfigField("boolean", "ALLOW_SCREENSHOTS", allowScreenshots.toString())
        }
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            buildConfigField("boolean", "ALLOW_SCREENSHOTS", "false")
            signingConfigs.findByName("release")?.let { signingConfig = it }
        }
    }

    sourceSets {
        getByName("main") {
            if (coreAvailable) {
                kotlin.srcDirs("src/uniffi/kotlin", coreGeneratedDir.path)
            } else {
                kotlin.srcDirs("src/nocore/kotlin")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources.excludes += setOf("/META-INF/{AL2.0,LGPL2.1}")
    }

    testOptions {
        unitTests.all {
            it.systemProperty("keyvora.vectors", testVectors.absolutePath)
            it.systemProperty("keyvora.coreAvailable", coreAvailable.toString())
            it.systemProperty("keyvora.mainSources", file("src/main").absolutePath)
            it.systemProperty("keyvora.requireHostCore", (project.findProperty("keyvora.requireHostCore") ?: "false").toString())
            if (hostCoreDir.exists()) {
                it.systemProperty("jna.library.path", hostCoreDir.absolutePath)
            }
        }
    }

    lint {
        abortOnError = true
        checkReleaseBuilds = false
        lintConfig = file("lint.xml")
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.fragment.ktx)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.process)
    implementation(libs.androidx.navigation.compose)
    implementation(libs.androidx.biometric)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons.core)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.play.services.auth)
    // UniFFI's generated Kotlin code loads the native library through JNA (Android AAR with libjnidispatch).
    implementation("${libs.jna.get()}@aar")
    debugImplementation(libs.androidx.compose.ui.tooling)

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.org.json)
    // Desktop JNA (with host jnidispatch) so CoreVectorsTest can load a host build of the core on the JVM.
    testImplementation(libs.jna)
}
