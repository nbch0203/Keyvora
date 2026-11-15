package com.keyvora.app.ui

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.keyvora.app.KeyvoraApp
import com.keyvora.app.vault.VaultManager

/** Single activity (FragmentActivity for BiometricPrompt). FLAG_SECURE hides content from screenshots/Recents. */
class MainActivity : FragmentActivity() {
    private val container by lazy { (application as KeyvoraApp).container }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge() // status/navigation bar icons follow the light/dark theme
        super.onCreate(savedInstanceState)
        applySecureWindow()
        setContent {
            KeyvoraTheme {
                CompositionLocalProvider(LocalAppContainer provides container) { KeyvoraRoot() }
            }
        }
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        container.autoLock.onUserInteraction()
    }
}

@Composable
fun KeyvoraRoot() {
    val c = LocalAppContainer.current
    val status by c.vault.status.collectAsStateWithLifecycle()
    val recoveryKey by c.recoveryKey.key.collectAsStateWithLifecycle()
    val rk = recoveryKey
    when {
        status == VaultManager.Status.UNLOCKED && rk != null -> RecoveryKeyScreen(rk) { c.recoveryKey.clear() }
        status == VaultManager.Status.NO_VAULT -> SetupScreen()
        status == VaultManager.Status.LOCKED -> UnlockScreen()
        else -> {
            MainNavigation()
            KeyringAdoptionHost()
        }
    }
}
