package com.keyvora.app.security

import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.IOException
import java.security.InvalidKeyException
import java.security.KeyStoreException
import java.security.ProviderException
import java.security.UnrecoverableKeyException
import java.security.cert.CertificateException

/** AUDIT AND-4: no Keystore failure may crash the unlock screen; only a lost key disables biometrics. */
class BiometricClassifyTest {
    @Test
    fun lostKeyInvalidatesBiometrics() {
        assertEquals(BiometricUnlock.Prepared.Invalidated, BiometricUnlock.classify(UnrecoverableKeyException("lock screen changed")))
    }

    @Test
    fun otherKeystoreFailuresFallBackToThePasswordWithoutDisabling() {
        for (e in listOf(KeyStoreException("busy"), InvalidKeyException("x"), ProviderException("keystore2"), IOException("io"),
            CertificateException("cert"), IllegalStateException("state"))) {
            assertEquals(e.toString(), BiometricUnlock.Prepared.Unavailable, BiometricUnlock.classify(e))
        }
    }
}
