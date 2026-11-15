package com.keyvora.app.vault

import com.keyvora.app.core.CoreBridge
import com.keyvora.app.core.CoreException
import com.keyvora.app.core.Entry
import com.keyvora.app.core.EntrySummary
import com.keyvora.app.core.KdfParams
import com.keyvora.app.core.MergeReport
import com.keyvora.app.core.VaultSession
import com.keyvora.app.sync.ExportSnapshot
import com.keyvora.app.sync.SyncLocal
import com.keyvora.app.sync.SyncState
import com.keyvora.app.sync.SyncStateStore
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.security.MessageDigest
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicLong

/**
 * Owns the single in-memory [VaultSession] and the encrypted local container.
 *
 * - Every core call runs on [worker] under one [Mutex], so mutations, exports and sync merges never interleave.
 * - After every mutation the container is exported and written atomically ([ContainerStorage]); the sync dirty flag
 *   is raised and listeners (debounced sync) are notified.
 * - [lock] wipes the DEK (core `lock()`) and drops the reference; it is safe to call from any thread.
 */
class VaultManager(
    val core: CoreBridge,
    private val storage: ContainerStorage,
    private val deviceId: () -> String,
    private val syncState: SyncStateStore,
    private val scope: CoroutineScope,
    private val clock: () -> Long = System::currentTimeMillis,
    private val worker: CoroutineDispatcher = Dispatchers.Default,
) : SyncLocal {

    enum class Status { NO_VAULT, LOCKED, UNLOCKED }

    private val _status = MutableStateFlow(if (storage.exists()) Status.LOCKED else Status.NO_VAULT)
    val status: StateFlow<Status> = _status.asStateFlow()

    /** Increments whenever vault content may have changed (local edit, merge, unlock). UI reloads on it. */
    private val _contentVersion = MutableStateFlow(0L)
    val contentVersion: StateFlow<Long> = _contentVersion.asStateFlow()

    private val mutex = Mutex()

    @Volatile
    private var session: VaultSession? = null

    @Volatile
    private var lockPending = false
    private val seq = AtomicLong(0)

    private val lockListeners = CopyOnWriteArrayList<() -> Unit>()
    private val unlockListeners = CopyOnWriteArrayList<() -> Unit>()
    private val localChangeListeners = CopyOnWriteArrayList<() -> Unit>()
    private val dataKeyChangedListeners = CopyOnWriteArrayList<() -> Unit>()

    val isUnlocked: Boolean get() = _status.value == Status.UNLOCKED

    fun addLockListener(l: () -> Unit) { lockListeners += l }
    fun addUnlockListener(l: () -> Unit) { unlockListeners += l }
    fun addLocalChangeListener(l: () -> Unit) { localChangeListeners += l }

    /** The DEK changed (rotation here, or adopted from another device): device-local wraps (biometrics) are stale. */
    fun addDataKeyChangedListener(l: () -> Unit) { dataKeyChangedListeners += l }

    // ---------------------------------------------------------------- lifecycle

    /**
     * Creates a new vault. The recovery key (shown once, never stored) is handed to [onRecoveryKey] before the
     * session becomes visible as unlocked, so the UI can show it first.
     */
    suspend fun create(master: String, onRecoveryKey: (String) -> Unit) = work {
        check(!storage.exists()) { "vault already exists" }
        val s = core.create(master, core.defaultKdfParams(), deviceId(), clock())
        try {
            val rk = s.takeRecoveryKey() ?: throw CoreException(CoreException.CRYPTO)
            storage.write(s.exportContainer())
            syncState.update { SyncState(vaultId = s.vaultId(), dirty = true) }
            onRecoveryKey(rk)
            install(s)
        } catch (e: Throwable) {
            s.lock()
            throw e
        }
    }

    suspend fun unlockWithPassword(master: String) = work {
        install(core.unlockWithPassword(readContainer(), master, deviceId()))
    }

    /** Unlocks with the recovery key and immediately sets a new master password (T15). */
    suspend fun unlockWithRecoveryKey(recoveryKey: String, newMaster: String) = work {
        val s = core.unlockWithRecoveryKey(readContainer(), recoveryKey, deviceId())
        try {
            s.resetMasterPasswordWithRecovery(recoveryKey, newMaster, core.defaultKdfParams())
            storage.write(s.exportContainer())
        } catch (e: Throwable) {
            s.lock()
            throw e
        }
        install(s)
        markLocalChange()
    }

    /** Biometric unlock: [dek] comes from the Android Keystore unwrap; the caller zeroes it afterwards. */
    suspend fun unlockWithDataKey(dek: ByteArray) = work {
        install(core.openWithDataKey(readContainer(), dek, deviceId()))
    }

    private fun readContainer(): String = storage.read() ?: throw CoreException(CoreException.NOT_FOUND)

    private fun install(s: VaultSession) {
        session?.lock()
        session = s
        lockPending = false
        val vid = s.vaultId()
        syncState.update { st ->
            when (st.vaultId) {
                null -> st.copy(vaultId = vid)
                vid -> st
                else -> SyncState(vaultId = vid, dirty = true)
            }
        }
        _status.value = Status.UNLOCKED
        _contentVersion.value++
        unlockListeners.forEach { runCatching(it) }
    }

    /** Locks now: wipes the DEK and drops the session. Callable from any thread (lifecycle callbacks). */
    fun lock() {
        if (session == null && _status.value != Status.UNLOCKED) return
        lockPending = true
        if (_status.value == Status.UNLOCKED) _status.value = Status.LOCKED
        lockListeners.forEach { runCatching(it) }
        if (mutex.tryLock()) {
            try { wipeIfPending() } finally { mutex.unlock() }
        } else {
            // A core call is running (e.g. Argon2): wipe right after it; reads/mutations already refuse (lockPending).
            scope.launch(worker) { mutex.withLock { wipeIfPending() } }
        }
    }

    private fun wipeIfPending() {
        if (!lockPending) return
        session?.lock()
        session = null
        lockPending = false
    }

    // ---------------------------------------------------------------- vault access

    suspend fun <T> read(block: (VaultSession) -> T): T = work { block(requireSession()) }

    /** Runs a mutation, then exports + persists the container and flags the change for sync. */
    suspend fun <T> mutate(block: (VaultSession) -> T): T = work {
        val s = requireSession()
        val result = block(s)
        storage.write(s.exportContainer())
        markLocalChange()
        result
    }

    fun now(): Long = clock()

    suspend fun listEntries(query: String): List<EntrySummary> =
        read { if (query.isBlank()) it.listEntries() else it.search(query) }

    suspend fun getEntry(id: String): Entry = read { it.getEntry(id) }

    suspend fun changeMasterPassword(current: String, next: String) =
        mutate { it.changeMasterPassword(current, next, core.defaultKdfParams()) }

    /** Returns the new recovery key (show once). */
    suspend fun rotateRecoveryKey(currentMaster: String): String = mutate {
        it.rotateRecoveryKey(currentMaster)
        it.takeRecoveryKey() ?: throw CoreException(CoreException.CRYPTO)
    }

    /**
     * Rotates the data key (H-1): new DEK, password slot and recovery key. Returns the new recovery key (show once).
     * Only protects data written from now on; copies made with the old key stay readable with it.
     */
    suspend fun rotateDataKey(currentMaster: String): String {
        val rk = mutate {
            it.rotateDataKey(currentMaster)
            it.takeRecoveryKey() ?: throw CoreException(CoreException.CRYPTO)
        }
        dataKeyChangedListeners.forEach { runCatching(it) }
        return rk
    }

    class AdoptResult(val report: MergeReport, val dataKeyChanged: Boolean)

    /**
     * ADR-013: adopts newer keys from [remoteContainer] after proving the master password that opens it, merging local
     * data. Persists the result and flags it for sync.
     */
    suspend fun adoptRemoteKeys(remoteContainer: String, master: String): AdoptResult {
        val result = work {
            val s = requireSession()
            val before = s.exportDataKey()
            try {
                val report = s.adoptRemoteKeys(remoteContainer, master)
                storage.write(s.exportContainer())
                val after = s.exportDataKey()
                val changed = !MessageDigest.isEqual(before, after)
                after.fill(0)
                markLocalChange()
                AdoptResult(report, changed)
            } finally {
                before.fill(0)
            }
        }
        if (result.dataKeyChanged) dataKeyChangedListeners.forEach { runCatching(it) }
        return result
    }

    suspend fun passwordKdfParams(): KdfParams = read { it.passwordKdfParams() }

    /** DEK copy for the biometric wrap. Caller must zero it. */
    suspend fun exportDataKey(): ByteArray = read { it.exportDataKey() }

    suspend fun vaultId(): String = read { it.vaultId() }

    /** Encrypted container for an export file. Works while locked (it is ciphertext). */
    suspend fun exportBackup(): String = work {
        val s = session?.takeIf { !lockPending }
        if (s != null) s.exportContainer().also(storage::write) else readContainer()
    }

    /** Imports an encrypted copy of THIS vault by merging it (never overwrites). VAULT_MISMATCH for another vault. */
    suspend fun importMerge(container: String): MergeReport = work {
        val s = requireSession()
        val r = s.mergeRemote(container)
        storage.write(s.exportContainer())
        markLocalChange()
        r
    }

    /**
     * Installs a container when there is no local vault (setup: import file / restore from Drive). It is validated by
     * the core on the first unlock; until then the user may discard it ([discardPendingImport]).
     */
    suspend fun installContainer(container: String) = work {
        check(session == null && !storage.exists()) { "local vault exists" }
        storage.write(container)
        _status.value = Status.LOCKED
    }

    /** Removes a never-unlocked imported container (only offered while `importPending`). */
    suspend fun discardPendingImport() = work {
        check(session == null) { "unlocked" }
        storage.delete()
        syncState.update { SyncState() }
        _status.value = Status.NO_VAULT
    }

    /** Entries of another container of the same vault (old export / Drive revision). */
    suspend fun previewContainer(container: String): List<EntrySummary> = read { it.previewContainer(container) }

    /** Copies entries from an older container as NEW entries (SYNC_PROTOCOL §5). */
    suspend fun restoreEntries(container: String, ids: List<String>): List<Entry> =
        mutate { it.restoreEntriesFrom(container, ids, clock()) }

    // ---------------------------------------------------------------- SyncLocal

    override suspend fun mergeRemoteAndPersist(remoteContainer: String): MergeReport = work {
        val s = requireSession()
        val r = s.mergeRemote(remoteContainer)
        storage.write(s.exportContainer())
        if (r.added + r.updated + r.removed > 0 || r.keyringAdopted || r.newConflicts.isNotEmpty()) _contentVersion.value++
        r
    }

    override suspend fun exportForUpload(): ExportSnapshot = work {
        val s = requireSession()
        val at = seq.get()
        val c = s.exportContainer()
        storage.write(c)
        ExportSnapshot(c, s.revision(), at)
    }

    override fun changeSeq(): Long = seq.get()

    // ---------------------------------------------------------------- internals

    private fun markLocalChange() {
        seq.incrementAndGet()
        syncState.update { it.copy(dirty = true) }
        _contentVersion.value++
        localChangeListeners.forEach { runCatching(it) }
    }

    private fun requireSession(): VaultSession {
        if (lockPending) throw CoreException(CoreException.LOCKED)
        return session ?: throw CoreException(CoreException.LOCKED)
    }

    private suspend fun <T> work(block: () -> T): T = withContext(worker) { mutex.withLock { block() } }
}
