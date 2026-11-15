package com.keyvora.app.sync

import com.keyvora.app.core.CoreException
import com.keyvora.app.vault.AppSettings
import com.keyvora.app.vault.VaultManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex

/**
 * Decides WHEN to sync (on unlock, debounced after local changes, manual, periodic retry while dirty) and runs one
 * [SyncEngine] at a time. Works only while the vault is unlocked and Drive is connected; offline changes stay
 * `dirty` until the next trigger.
 */
class SyncCoordinator(
    private val vault: VaultManager,
    private val settings: AppSettings,
    private val stateStore: SyncStateStore,
    private val remoteFactory: () -> RemoteStore,
    private val keyring: KeyringAdoption,
    private val scope: CoroutineScope,
    private val debounceMs: Long = 3_000,
    private val retryMs: Long = 5 * 60_000,
) {
    data class UiState(
        val connected: Boolean = false,
        val running: Boolean = false,
        val state: SyncState = SyncState(),
        val lastResult: SyncResult? = null,
    )

    private val _ui = MutableStateFlow(UiState())
    val ui: StateFlow<UiState> = _ui.asStateFlow()

    private val runMutex = Mutex()

    @Volatile
    private var rerun = false
    private var debounceJob: Job? = null
    private var retryJob: Job? = null

    fun install() {
        vault.addUnlockListener { requestSync() }
        vault.addLocalChangeListener { scheduleDebounced() }
        vault.addLockListener {
            debounceJob?.cancel()
            retryJob?.cancel()
        }
        refresh()
    }

    fun refresh(running: Boolean = _ui.value.running) {
        _ui.value = _ui.value.copy(connected = settings.driveConnected, running = running, state = stateStore.load())
    }

    private fun scheduleDebounced() {
        refresh()
        debounceJob?.cancel()
        debounceJob = scope.launch {
            delay(debounceMs)
            runOnce()
        }
    }

    fun requestSync() {
        scope.launch { runOnce() }
    }

    /** Manual "Sincronizar ahora". */
    suspend fun syncNow(): SyncResult? = runOnce()

    fun onConnected() {
        settings.driveConnected = true
        requestSync()
    }

    fun disconnect() {
        settings.driveConnected = false
        debounceJob?.cancel()
        retryJob?.cancel()
        stateStore.update { it.copy(lastError = null) }
        refresh()
    }

    private suspend fun runOnce(): SyncResult? {
        if (!settings.driveConnected || !vault.isUnlocked) {
            refresh()
            return null
        }
        if (!runMutex.tryLock()) {
            rerun = true
            return null
        }
        var last: SyncResult? = null
        try {
            do {
                rerun = false
                refresh(running = true)
                last = SyncEngine(remoteFactory(), vault, stateStore).sync()
                _ui.value = _ui.value.copy(lastResult = last)
                last.keyringChangedContainer?.let { keyring.offer(KeyringAdoption.Source.SYNC, it) }
            } while (rerun && vault.isUnlocked && settings.driveConnected)
        } finally {
            runMutex.unlock()
            refresh(running = false)
        }
        scheduleRetryIfNeeded(last)
        return last
    }

    private fun scheduleRetryIfNeeded(result: SyncResult?) {
        retryJob?.cancel()
        val transient = result?.status == SyncResult.Status.FAILED && result.error in RETRY_LATER
        val blocked = result?.error == CoreException.LOCKED || result?.error == CoreException.KEYRING_CHANGED
        if ((transient || stateStore.load().dirty) && !blocked) {
            retryJob = scope.launch {
                delay(retryMs)
                runOnce()
            }
        }
    }

    private companion object {
        val RETRY_LATER = setOf(
            RemoteErrorCode.NETWORK.name, RemoteErrorCode.RATE_LIMITED.name, SyncEngine.CONFLICT_RETRY_EXHAUSTED,
        )
    }
}
