package com.keyvora.app.vault

import android.content.SharedPreferences
import android.util.AtomicFile
import androidx.core.content.edit
import java.io.File
import java.io.FileNotFoundException
import java.util.UUID

/** Local copy of the ENCRYPTED container (the only vault data ever written to disk). */
interface ContainerStorage {
    fun exists(): Boolean
    fun read(): String?
    fun write(container: String)
    fun delete()
}

/** `filesDir/vault.json`, written atomically (write to backup + fsync + rename) with [AtomicFile]. */
class AtomicFileContainerStorage(file: File) : ContainerStorage {
    private val atomic = AtomicFile(file)
    private val base = file

    @Synchronized
    override fun exists(): Boolean = base.exists()

    @Synchronized
    override fun read(): String? = try {
        atomic.readFully().toString(Charsets.UTF_8)
    } catch (_: FileNotFoundException) {
        null
    }

    @Synchronized
    override fun write(container: String) {
        val out = atomic.startWrite()
        try {
            out.write(container.toByteArray(Charsets.UTF_8))
            atomic.finishWrite(out)
        } catch (e: Exception) {
            atomic.failWrite(out)
            throw e
        }
    }

    @Synchronized
    override fun delete() = atomic.delete()
}

class InMemoryContainerStorage(private var value: String? = null) : ContainerStorage {
    @Synchronized override fun exists() = value != null
    @Synchronized override fun read() = value
    @Synchronized override fun write(container: String) { value = container }
    @Synchronized override fun delete() { value = null }
}

/** Auto-lock delays offered in settings. 0 = immediately when the app goes to background. */
enum class AutoLockDelay(val minutes: Int) {
    IMMEDIATE(0), ONE(1), FIVE(5), FIFTEEN(15);

    val millis: Long get() = minutes * 60_000L

    companion object {
        fun fromMinutes(m: Int) = entries.firstOrNull { it.minutes == m } ?: ONE
    }
}

/** App appearance chosen in Ajustes (follows the system by default). */
enum class ThemeMode { SYSTEM, LIGHT, DARK }

/** Non-secret settings in SharedPreferences (no secrets are ever stored here). */
class AppSettings(private val prefs: SharedPreferences) {
    /** Random per-installation id ([A-Za-z0-9-], VAULT_FORMAT §5); a fresh install gets a new one (no backups). */
    val deviceId: String
        @Synchronized get() = prefs.getString(K_DEVICE, null) ?: UUID.randomUUID().toString().also {
            prefs.edit(commit = true) { putString(K_DEVICE, it) }
        }

    var autoLock: AutoLockDelay
        get() = AutoLockDelay.fromMinutes(prefs.getInt(K_AUTOLOCK, AutoLockDelay.ONE.minutes))
        set(v) { prefs.edit { putInt(K_AUTOLOCK, v.minutes) } }

    var biometricEnabled: Boolean
        get() = prefs.getBoolean(K_BIO, false)
        set(v) { prefs.edit { putBoolean(K_BIO, v) } }

    var driveConnected: Boolean
        get() = prefs.getBoolean(K_DRIVE, false)
        set(v) { prefs.edit { putBoolean(K_DRIVE, v) } }

    /** Biometrics were turned off because the data key changed; suggest re-enabling. */
    var biometricNeedsReenable: Boolean
        get() = prefs.getBoolean(K_BIO_REENABLE, false)
        set(v) { prefs.edit { putBoolean(K_BIO_REENABLE, v) } }

    /** A container was imported/restored but never unlocked yet: the user may still discard it. */
    var importPending: Boolean
        get() = prefs.getBoolean(K_IMPORT_PENDING, false)
        set(v) { prefs.edit(commit = true) { putBoolean(K_IMPORT_PENDING, v) } }

    var themeMode: ThemeMode
        get() = ThemeMode.entries.firstOrNull { it.name == prefs.getString(K_THEME, null) } ?: ThemeMode.SYSTEM
        set(v) { prefs.edit { putString(K_THEME, v.name) } }

    private companion object {
        const val K_DEVICE = "deviceId"
        const val K_THEME = "themeMode"
        const val K_AUTOLOCK = "autoLockMinutes"
        const val K_BIO = "biometricEnabled"
        const val K_BIO_REENABLE = "biometricNeedsReenable"
        const val K_DRIVE = "driveConnected"
        const val K_IMPORT_PENDING = "importPending"
    }
}
