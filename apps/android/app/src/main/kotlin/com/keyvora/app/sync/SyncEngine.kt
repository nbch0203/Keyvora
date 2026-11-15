package com.keyvora.app.sync

import com.keyvora.app.core.CoreException
import com.keyvora.app.core.MergeReport
import kotlinx.coroutines.delay
import kotlin.random.Random

data class SyncResult(
    val status: Status,
    /** Error code (CoreException / RemoteErrorCode / CONFLICT_RETRY_EXHAUSTED) when [status] = FAILED. */
    val error: String? = null,
    /** The remote container had a lower revision than one already seen (possible rollback, SYNC_PROTOCOL §3). */
    val rollbackWarning: Boolean = false,
    /** Another device changed the master password / recovery key (keyring adopted from remote). */
    val keyringAdopted: Boolean = false,
    val keyringConflict: Boolean = false,
    val newConflicts: List<String> = emptyList(),
    val changedLocally: Boolean = false,
    val rounds: Int = 0,
    /** Adopted keys use weaker KDF parameters (only set by key adoption). */
    val kdfWeakened: Boolean = false,
    /**
     * error = KEYRING_CHANGED: the (encrypted) remote container whose newer keys must be adopted with the master
     * password (`adoptRemoteKeys`, ADR-013) before sync can continue.
     */
    val keyringChangedContainer: String? = null,
) {
    enum class Status { CREATED, UP_TO_DATE, DOWNLOADED, UPLOADED, FAILED }

    override fun toString() = "SyncResult(status=$status, error=$error, rounds=$rounds)"
}

/**
 * Client sync algorithm of docs/SYNC_PROTOCOL.md §3:
 * - never uploads without first merging the latest remote version read;
 * - re-checks `headRevisionId` right before uploading;
 * - after uploading, lists revisions and merges every revision written between the one we merged and ours;
 * - at most [maxRounds] rounds, then `CONFLICT_RETRY_EXHAUSTED` (data stays safe locally);
 * - NETWORK / RATE_LIMITED are retried with exponential backoff (1 s, 2 s, 4 s… max 60 s) with jitter;
 * - AUTH_REQUIRED, REMOTE_ERROR and core errors (INTEGRITY_ERROR, VAULT_MISMATCH…) fail closed without uploading;
 * - KEYRING_CHANGED (newer keys elsewhere) stops the sync and returns the remote container so the user can adopt the
 *   keys with the master password (ADR-013); keys are never adopted silently.
 */
class SyncEngine(
    private val remote: RemoteStore,
    private val local: SyncLocal,
    private val state: SyncStateStore,
    private val clock: () -> Long = System::currentTimeMillis,
    private val sleep: suspend (Long) -> Unit = { delay(it) },
    private val random: Random = Random.Default,
    private val maxRounds: Int = 5,
    private val maxTransientRetries: Int = 4,
) {
    private class Acc {
        var rollback = false
        var keyringAdopted = false
        var keyringConflict = false
        var changedLocally = false
        var kdfWeakened = false
        var keyringContainer: String? = null
        val newConflicts = linkedSetOf<String>()
        var rounds = 0

        fun record(r: MergeReport) {
            keyringAdopted = keyringAdopted || r.keyringAdopted
            keyringConflict = keyringConflict || r.keyringConflict
            kdfWeakened = kdfWeakened || r.kdfWeakened
            changedLocally = changedLocally || r.added + r.updated + r.removed > 0 || r.keyringAdopted
            newConflicts += r.newConflicts
        }

        fun result(status: SyncResult.Status, error: String? = null) = SyncResult(
            status, error, rollback, keyringAdopted, keyringConflict, newConflicts.toList(), changedLocally, rounds,
            kdfWeakened, keyringContainer.takeIf { error == CoreException.KEYRING_CHANGED },
        )
    }

    private class RetryExhausted : Exception("CONFLICT_RETRY_EXHAUSTED")

    suspend fun sync(): SyncResult {
        val acc = Acc()
        var attempt = 0
        while (true) {
            try {
                val result = runRounds(acc)
                state.update { it.copy(lastError = null, lastSyncAt = clock(), rollbackWarning = acc.rollback) }
                return result
            } catch (e: RemoteException) {
                if (e.code.retryable && attempt < maxTransientRetries) {
                    sleep(backoffMs(attempt, e.retryAfterMs))
                    attempt++
                    continue
                }
                return fail(acc, e.code.name)
            } catch (e: CoreException) {
                return fail(acc, e.code)
            } catch (e: RetryExhausted) {
                return fail(acc, CONFLICT_RETRY_EXHAUSTED)
            }
        }
    }

    private fun fail(acc: Acc, code: String): SyncResult {
        state.update { it.copy(lastError = code, rollbackWarning = it.rollbackWarning || acc.rollback) }
        return acc.result(SyncResult.Status.FAILED, code)
    }

    /** Exponential backoff with jitter in [base/2, base], base = min(60 s, 1 s · 2^attempt). */
    fun backoffMs(attempt: Int, retryAfterMs: Long? = null): Long {
        val base = (INITIAL_BACKOFF_MS shl attempt.coerceIn(0, 16)).coerceAtMost(MAX_BACKOFF_MS)
        val jittered = base / 2 + random.nextLong(base / 2 + 1)
        return maxOf(jittered, retryAfterMs ?: 0).coerceAtMost(MAX_BACKOFF_MS)
    }

    private suspend fun runRounds(acc: Acc): SyncResult {
        repeat(maxRounds) {
            acc.rounds++
            val s = state.load()
            val meta = remote.getMetadata()

            if (meta == null) {
                // First upload: nothing remote to merge.
                val snap = local.exportForUpload()
                val created = remote.create(snap.container)
                state.update {
                    it.copy(
                        fileId = created.fileId,
                        lastSyncedHeadRevisionId = created.headRevisionId,
                        highestRemoteRevision = maxOf(it.highestRemoteRevision, snap.revision),
                        dirty = local.changeSeq() != snap.changeSeq,
                    )
                }
                return acc.result(SyncResult.Status.CREATED)
            }

            if (meta.fileId == s.fileId && meta.headRevisionId == s.lastSyncedHeadRevisionId && !s.dirty) {
                return acc.result(SyncResult.Status.UP_TO_DATE)
            }

            val seqBeforeMerge = local.changeSeq()
            val downloaded = try {
                remote.download(meta.fileId)
            } catch (e: RemoteException) {
                if (e.httpStatus == 404) return@repeat // file vanished meanwhile: re-read metadata
                throw e
            }
            val report = merge(acc, downloaded.content) // fails closed on INTEGRITY_ERROR/VAULT_MISMATCH/KEYRING_CHANGED
            acc.record(report)
            if (report.remoteRevision < s.highestRemoteRevision) acc.rollback = true
            state.update {
                it.copy(
                    fileId = meta.fileId,
                    highestRemoteRevision = maxOf(it.highestRemoteRevision, report.remoteRevision),
                )
            }

            if (!report.needsUpload) {
                state.update {
                    it.copy(
                        lastSyncedHeadRevisionId = downloaded.headRevisionId,
                        dirty = local.changeSeq() != seqBeforeMerge,
                    )
                }
                return acc.result(SyncResult.Status.DOWNLOADED)
            }

            // Local has content the remote lacks: remember it even if the upload below fails.
            state.update { it.copy(dirty = true) }

            val meta2 = remote.getMetadata()
            if (meta2 == null || meta2.fileId != meta.fileId || meta2.headRevisionId != downloaded.headRevisionId) {
                return@repeat // someone wrote while we merged: start over (merge again before uploading)
            }

            val snap = local.exportForUpload()
            val uploaded = try {
                remote.update(meta.fileId, snap.container)
            } catch (e: RemoteException) {
                if (e.httpStatus == 404) return@repeat
                throw e
            }

            val revisions = remote.listRevisions(meta.fileId)
            val intermediate = intermediateRevisions(revisions, downloaded.headRevisionId, uploaded.headRevisionId)
            for (rev in intermediate) {
                val content = remote.downloadRevision(meta.fileId, rev.id)
                acc.record(merge(acc, content))
            }
            val dirty = intermediate.isNotEmpty() || local.changeSeq() != snap.changeSeq
            state.update {
                it.copy(
                    lastSyncedHeadRevisionId = uploaded.headRevisionId,
                    highestRemoteRevision = maxOf(it.highestRemoteRevision, snap.revision),
                    dirty = dirty,
                )
            }
            if (intermediate.isEmpty()) return acc.result(SyncResult.Status.UPLOADED)
            // Intermediate writes were merged locally: next round uploads the union.
        }
        throw RetryExhausted()
    }

    private suspend fun merge(acc: Acc, content: String): MergeReport = try {
        local.mergeRemoteAndPersist(content)
    } catch (e: CoreException) {
        if (e.code == CoreException.KEYRING_CHANGED) acc.keyringContainer = content
        throw e
    }

    companion object {
        const val CONFLICT_RETRY_EXHAUSTED = "CONFLICT_RETRY_EXHAUSTED"
        const val INITIAL_BACKOFF_MS = 1_000L
        const val MAX_BACKOFF_MS = 60_000L

        /**
         * Revisions strictly between [baseId] (the one we merged) and [uploadedId] (ours), in chronological order.
         * If [baseId] is no longer listed (purged), every revision before ours is merged (merge is idempotent).
         * If ours is not listed yet, everything after the base is considered intermediate.
         */
        fun intermediateRevisions(revisions: List<RevisionInfo>, baseId: String, uploadedId: String): List<RevisionInfo> {
            val baseIdx = revisions.indexOfFirst { it.id == baseId }
            val upIdx = revisions.indexOfFirst { it.id == uploadedId }
            val from = if (baseIdx >= 0) baseIdx + 1 else 0
            val to = if (upIdx >= 0) upIdx else revisions.size
            if (from >= to) return emptyList()
            return revisions.subList(from, to).filter { it.id != uploadedId && it.id != baseId }
        }
    }
}
