package com.keyvora.app.sync

import android.content.SharedPreferences
import androidx.core.content.edit
import com.keyvora.app.core.MergeReport

/** Non-secret local sync state (docs/SYNC_PROTOCOL.md §1). */
data class SyncState(
    /** Vault the state belongs to; a different vault resets it. */
    val vaultId: String? = null,
    val fileId: String? = null,
    val lastSyncedHeadRevisionId: String? = null,
    val highestRemoteRevision: Long = 0,
    /** Local changes not yet uploaded. */
    val dirty: Boolean = false,
    val lastSyncAt: Long? = null,
    val lastError: String? = null,
    val rollbackWarning: Boolean = false,
)

interface SyncStateStore {
    fun load(): SyncState

    /** Atomic read-modify-write. */
    fun update(transform: (SyncState) -> SyncState): SyncState
}

class InMemorySyncStateStore(initial: SyncState = SyncState()) : SyncStateStore {
    private var state = initial

    @Synchronized
    override fun load(): SyncState = state

    @Synchronized
    override fun update(transform: (SyncState) -> SyncState): SyncState {
        state = transform(state)
        return state
    }
}

class PrefsSyncStateStore(private val prefs: SharedPreferences) : SyncStateStore {
    @Synchronized
    override fun load(): SyncState = SyncState(
        vaultId = prefs.getString(K_VAULT, null),
        fileId = prefs.getString(K_FILE, null),
        lastSyncedHeadRevisionId = prefs.getString(K_HEAD, null),
        highestRemoteRevision = prefs.getLong(K_HIGHEST, 0),
        dirty = prefs.getBoolean(K_DIRTY, false),
        lastSyncAt = prefs.getLong(K_LAST_AT, 0).takeIf { it > 0 },
        lastError = prefs.getString(K_ERROR, null),
        rollbackWarning = prefs.getBoolean(K_ROLLBACK, false),
    )

    @Synchronized
    override fun update(transform: (SyncState) -> SyncState): SyncState {
        val s = transform(load())
        // Synchronous write: the dirty flag / revision ids must survive a process kill right after a sync step.
        prefs.edit(commit = true) {
            putString(K_VAULT, s.vaultId)
            putString(K_FILE, s.fileId)
            putString(K_HEAD, s.lastSyncedHeadRevisionId)
            putLong(K_HIGHEST, s.highestRemoteRevision)
            putBoolean(K_DIRTY, s.dirty)
            putLong(K_LAST_AT, s.lastSyncAt ?: 0)
            putString(K_ERROR, s.lastError)
            putBoolean(K_ROLLBACK, s.rollbackWarning)
        }
        return s
    }

    private companion object {
        const val K_VAULT = "sync.vaultId"
        const val K_FILE = "sync.fileId"
        const val K_HEAD = "sync.lastSyncedHeadRevisionId"
        const val K_HIGHEST = "sync.highestRemoteRevision"
        const val K_DIRTY = "sync.dirty"
        const val K_LAST_AT = "sync.lastSyncAt"
        const val K_ERROR = "sync.lastError"
        const val K_ROLLBACK = "sync.rollbackWarning"
    }
}

/** Container exported for upload, with the local change counter at export time. */
class ExportSnapshot(val container: String, val revision: Long, val changeSeq: Long) {
    override fun toString() = "ExportSnapshot(revision=$revision, changeSeq=$changeSeq)"
}

/** What the sync engine needs from the local (unlocked) vault. Implemented by VaultManager. */
interface SyncLocal {
    /** Merges a remote container (core `mergeRemote`) and atomically persists the merged encrypted container. */
    suspend fun mergeRemoteAndPersist(remoteContainer: String): MergeReport

    /** Exports (and persists) the current container. */
    suspend fun exportForUpload(): ExportSnapshot

    /** Monotonic counter of local user mutations (in memory). */
    fun changeSeq(): Long
}
