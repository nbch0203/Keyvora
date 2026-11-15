package com.keyvora.app.security

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import com.keyvora.app.core.CoreException
import com.keyvora.app.vault.AppSettings
import com.keyvora.app.vault.VaultManager
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileNotFoundException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Optional biometric unlock (ADR-004/ADR-011): an AES-256-GCM key in the AndroidKeyStore that requires a
 * BIOMETRIC_STRONG authentication per use and is invalidated when biometrics are enrolled, wraps a copy of the DEK
 * (`exportDataKey()`). Ciphertext + IV live in `filesDir/biometric_dek.bin`, bound to the vault id (GCM AAD).
 * Device-local only: never exported, backed up or synced. Biometrics never replace the master password.
 */
class BiometricUnlock(
    private val context: Context,
    private val settings: AppSettings,
    private val vault: VaultManager,
    private val blobFile: File = File(context.filesDir, "biometric_dek.bin"),
) {
    sealed interface Prepared {
        class Ready(val cipher: Cipher) : Prepared
        data object NotEnabled : Prepared

        /** New biometrics enrolled or lock screen removed: blob deleted, password required. */
        data object Invalidated : Prepared
    }

    fun isHardwareAvailable(): Boolean =
        BiometricManager.from(context).canAuthenticate(BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS

    fun isEnabled(): Boolean = settings.biometricEnabled && blobFile.exists()

    /** Step 1 of enabling (session must be unlocked): a fresh key and an ENCRYPT cipher for the CryptoObject. */
    fun prepareEnable(): Cipher {
        deleteKey()
        val key = generateKey()
        return Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key) }
    }

    /** Step 2, after BiometricPrompt succeeded with the cipher of [prepareEnable]. */
    suspend fun finishEnable(cipher: Cipher) {
        val vaultId = vault.vaultId()
        val dek = vault.exportDataKey()
        try {
            cipher.updateAAD(vaultId.toByteArray(Charsets.UTF_8))
            val ct = cipher.doFinal(dek)
            writeBlob(Blob(vaultId, cipher.iv, ct))
            settings.biometricEnabled = true
            settings.biometricNeedsReenable = false
        } finally {
            dek.fill(0)
        }
    }

    fun prepareUnlock(): Prepared {
        if (!settings.biometricEnabled) return Prepared.NotEnabled
        val blob = readBlob() ?: return Prepared.NotEnabled.also { disable() }
        return try {
            val key = loadKey() ?: return Prepared.Invalidated.also { disable() }
            Prepared.Ready(Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, blob.iv)) })
        } catch (_: KeyPermanentlyInvalidatedException) {
            disable()
            Prepared.Invalidated
        }
    }

    /** After BiometricPrompt succeeded with the cipher of [prepareUnlock]: unwrap the DEK and open the vault. */
    suspend fun finishUnlock(cipher: Cipher) {
        val blob = readBlob() ?: throw CoreException(CoreException.INVALID_CREDENTIALS)
        val dek = try {
            cipher.updateAAD(blob.vaultId.toByteArray(Charsets.UTF_8))
            cipher.doFinal(blob.ciphertext)
        } catch (e: Exception) {
            disable()
            throw CoreException(CoreException.INVALID_CREDENTIALS, cause = e)
        }
        try {
            vault.unlockWithDataKey(dek)
        } catch (e: CoreException) {
            // DEK no longer opens this container (vault replaced): fall back to the password.
            if (e.code == CoreException.INVALID_CREDENTIALS || e.code == CoreException.INTEGRITY_ERROR) disable()
            throw e
        } finally {
            dek.fill(0)
        }
    }

    fun disable() {
        AtomicFile(blobFile).delete()
        deleteKey()
        settings.biometricEnabled = false
    }

    // ------------------------------------------------------------------ keystore

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun loadKey(): SecretKey? = keyStore().getKey(KEY_ALIAS, null) as? SecretKey

    private fun deleteKey() {
        try {
            keyStore().deleteEntry(KEY_ALIAS)
        } catch (_: Exception) {
            // Absent key: nothing to delete.
        }
    }

    private fun generateKey(): SecretKey {
        val spec = KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .apply {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) setUnlockedDeviceRequired(true)
            }
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE).run {
            init(spec)
            generateKey()
        }
    }

    // ------------------------------------------------------------------ blob (vaultId, iv, ciphertext)

    private class Blob(val vaultId: String, val iv: ByteArray, val ciphertext: ByteArray)

    private fun writeBlob(b: Blob) {
        val bytes = ByteArrayOutputStream().use { bos ->
            DataOutputStream(bos).use { out ->
                out.writeInt(BLOB_VERSION)
                out.writeUTF(b.vaultId)
                out.writeInt(b.iv.size); out.write(b.iv)
                out.writeInt(b.ciphertext.size); out.write(b.ciphertext)
            }
            bos.toByteArray()
        }
        val af = AtomicFile(blobFile)
        val os = af.startWrite()
        try {
            os.write(bytes)
            af.finishWrite(os)
        } catch (e: Exception) {
            af.failWrite(os)
            throw e
        }
    }

    private fun readBlob(): Blob? = try {
        DataInputStream(ByteArrayInputStream(AtomicFile(blobFile).readFully())).use { input ->
            if (input.readInt() != BLOB_VERSION) return null
            val vaultId = input.readUTF()
            val iv = ByteArray(input.readInt().also { require(it in 12..32) }).also { input.readFully(it) }
            val ct = ByteArray(input.readInt().also { require(it in 16..256) }).also { input.readFully(it) }
            Blob(vaultId, iv, ct)
        }
    } catch (_: FileNotFoundException) {
        null
    } catch (_: Exception) {
        null
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS = "keyvora.biometric.dek.v1"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val BLOB_VERSION = 1
    }
}
