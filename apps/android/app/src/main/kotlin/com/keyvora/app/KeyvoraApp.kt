package com.keyvora.app

import android.app.Application
import android.content.Context
import com.keyvora.app.autofill.AutofillTrust
import com.keyvora.app.autofill.CallerResolver
import com.keyvora.app.autofill.PendingSaveStore
import com.keyvora.app.autofill.PrefsTrustPins
import com.keyvora.app.core.CoreBridge
import com.keyvora.app.core.CoreBridgeFactory
import com.keyvora.app.security.AutoLockController
import com.keyvora.app.security.BiometricUnlock
import com.keyvora.app.security.ClipboardGuard
import com.keyvora.app.sync.GoogleAuthProvider
import com.keyvora.app.sync.GoogleDriveRemoteStore
import com.keyvora.app.sync.HttpUrlConnectionTransport
import com.keyvora.app.sync.KeyringAdoption
import com.keyvora.app.sync.PrefsSyncStateStore
import com.keyvora.app.sync.RemoteStore
import com.keyvora.app.sync.SyncCoordinator
import com.keyvora.app.vault.AppSettings
import com.keyvora.app.vault.AtomicFileContainerStorage
import com.keyvora.app.vault.VaultManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.File

class KeyvoraApp : Application() {
    lateinit var container: AppContainer
        private set

    override fun onCreate() {
        super.onCreate()
        container = AppContainer(this)
    }
}

/** Recovery key waiting to be shown once (after create / rotate). Memory only; cleared on lock. */
class RecoveryKeyHolder {
    private val _key = MutableStateFlow<String?>(null)
    val key: StateFlow<String?> = _key.asStateFlow()
    fun set(value: String) { _key.value = value }
    fun clear() { _key.value = null }
}

/** Manual dependency container (single process). Must be created on the main thread. */
class AppContainer(app: Application) {
    val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    val mainScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    val core: CoreBridge = CoreBridgeFactory.create()
    val settings = AppSettings(app.getSharedPreferences("keyvora_settings", Context.MODE_PRIVATE))

    /** Light / dark / system appearance, observed by KeyvoraTheme in every activity. */
    val themeMode = kotlinx.coroutines.flow.MutableStateFlow(settings.themeMode)
    val syncState = PrefsSyncStateStore(app.getSharedPreferences("keyvora_sync", Context.MODE_PRIVATE))
    val vault = VaultManager(
        core = core,
        storage = AtomicFileContainerStorage(File(app.filesDir, "vault.json")),
        deviceId = { settings.deviceId },
        syncState = syncState,
        scope = appScope,
    )
    val clipboard = ClipboardGuard(app, mainScope)
    val autoLock = AutoLockController(vault, settings, clipboard, mainScope)
    val biometric = BiometricUnlock(app, settings, vault)
    val googleAuth = GoogleAuthProvider(app)
    private val http = HttpUrlConnectionTransport()
    val pendingSaves = PendingSaveStore()
    val callerResolver = CallerResolver(app)
    /**
     * Device-local signing-certificate pins of associated apps (CONTRACTS §4.1). Browser pins from the TOFU era are
     * dropped once: browsers are now checked against their official certificates.
     */
    val trustPins = PrefsTrustPins(app.getSharedPreferences("keyvora_autofill_pins", Context.MODE_PRIVATE))
        .also(AutofillTrust::forgetBrowserPins)
    val keyring = KeyringAdoption(vault)
    val recoveryKey = RecoveryKeyHolder()

    fun driveStore(): RemoteStore = GoogleDriveRemoteStore(http, googleAuth)

    val sync = SyncCoordinator(vault, settings, syncState, ::driveStore, keyring, appScope)

    init {
        vault.addLockListener {
            clipboard.clearIfOurs()
            recoveryKey.clear()
            pendingSaves.clear()
            keyring.dismiss()
        }
        // New DEK (rotation here or adopted from another device): the biometric wrap is stale.
        vault.addDataKeyChangedListener {
            if (biometric.isEnabled()) {
                biometric.disable()
                settings.biometricNeedsReenable = true
            }
        }
        keyring.addAdoptedListener { sync.requestSync() }
        vault.addUnlockListener {
            if (settings.importPending) settings.importPending = false
        }
        autoLock.install()
        sync.install()
    }
}
