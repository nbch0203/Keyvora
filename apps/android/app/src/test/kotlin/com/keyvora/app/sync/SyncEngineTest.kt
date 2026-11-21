package com.keyvora.app.sync

import com.keyvora.app.core.CoreException
import com.keyvora.app.core.EntryInput
import com.keyvora.app.testing.FakeCoreBridge
import com.keyvora.app.vault.InMemoryContainerStorage
import com.keyvora.app.vault.VaultManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import kotlin.random.Random

private const val MASTER = "correct horse battery"
private const val NEW_MASTER = "a brand new master password"

class SyncEngineTest {
    private val core = FakeCoreBridge()
    private val remote = InMemoryRemoteStore()

    private inner class Device(val name: String, initialContainer: String? = null) {
        val storage = InMemoryContainerStorage(initialContainer)
        val state = InMemorySyncStateStore()
        val sleeps = mutableListOf<Long>()
        var now = 1_000L
        val vault = VaultManager(
            core, storage, { name }, state, CoroutineScope(Dispatchers.Unconfined),
            clock = { now++ }, worker = Dispatchers.Unconfined,
        )

        fun engine(maxRounds: Int = 5) =
            SyncEngine(remote, vault, state, clock = { now }, sleep = { sleeps += it }, random = Random(7), maxRounds = maxRounds)

        suspend fun sync(maxRounds: Int = 5) = engine(maxRounds).sync()

        suspend fun add(title: String) {
            now += 10
            vault.mutate { it.createEntry(EntryInput(title, "user", "pw-$title", emptyList(), ""), now) }
        }

        suspend fun titles(): Set<String> = vault.listEntries("").map { it.title }.toSet()
    }

    private suspend fun newVault(): Device = Device("devA").also { it.vault.create(MASTER) {} }

    /** Second device of the same vault, starting from a copy of [from]'s local container. */
    private suspend fun cloneOf(from: Device, name: String): Device =
        Device(name, from.storage.read()).also { it.vault.unlockWithPassword(MASTER) }

    private fun remoteTitles(): Set<String> = FakeCoreBridge.entryTitles(remote.head!!.content)

    @Test
    fun firstUploadCreatesRemoteFile() = runTest {
        val a = newVault()
        a.add("GitHub")
        val r = a.sync()
        assertEquals(SyncResult.Status.CREATED, r.status)
        assertEquals(1, remote.revisions.size)
        assertEquals(setOf("GitHub"), remoteTitles())
        val s = a.state.load()
        assertEquals("file-1", s.fileId)
        assertEquals(remote.head!!.id, s.lastSyncedHeadRevisionId)
        assertFalse(s.dirty)
        assertNull(s.lastError)
    }

    @Test
    fun upToDateDoesNotDownloadOrUpload() = runTest {
        val a = newVault()
        a.add("GitHub")
        a.sync()
        remote.calls.clear()
        val r = a.sync()
        assertEquals(SyncResult.Status.UP_TO_DATE, r.status)
        assertEquals(listOf("getMetadata"), remote.calls)
    }

    @Test
    fun remoteNewerIsDownloadedWithoutUpload() = runTest {
        val a = newVault()
        a.add("GitHub")
        a.sync()
        val b = cloneOf(a, "devB")
        b.add("Banco")
        assertEquals(SyncResult.Status.UPLOADED, b.sync().status)

        remote.calls.clear()
        val r = a.sync()
        assertEquals(SyncResult.Status.DOWNLOADED, r.status)
        assertTrue(r.changedLocally)
        assertFalse("must not upload", remote.calls.contains("update"))
        assertEquals(setOf("GitHub", "Banco"), a.titles())
        assertEquals(remote.head!!.id, a.state.load().lastSyncedHeadRevisionId)
        assertFalse(a.state.load().dirty)
    }

    @Test
    fun concurrentChangesAreMergedBeforeUpload() = runTest {
        val a = newVault()
        a.sync()
        val b = cloneOf(a, "devB")
        a.add("A-only")
        b.add("B-only")
        b.sync()
        val r = a.sync()
        assertEquals(SyncResult.Status.UPLOADED, r.status)
        assertEquals(setOf("A-only", "B-only"), remoteTitles())
        assertEquals(setOf("A-only", "B-only"), a.titles())
    }

    @Test
    fun interleavedWriteAfterPrecheckIsDetectedAndMerged() = runTest {
        val a = newVault()
        a.add("base")
        a.sync()
        val b = cloneOf(a, "devB")
        b.add("B-interleaved")
        val bContainer = b.vault.exportForUpload().container

        a.add("A-new")
        var fired = false
        remote.beforeUpdate = {
            if (!fired) {
                fired = true
                remote.externalWrite(bContainer) // B writes between A's headRevisionId check and A's upload
            }
        }
        val r = a.sync()
        assertTrue(fired)
        assertEquals(SyncResult.Status.UPLOADED, r.status)
        assertEquals("intermediate revision forces a second round", 2, r.rounds)
        assertEquals(setOf("base", "A-new", "B-interleaved"), remoteTitles())
        assertEquals(setOf("base", "A-new", "B-interleaved"), a.titles())
        assertTrue(remote.calls.contains("downloadRevision"))
        assertFalse(a.state.load().dirty)
    }

    @Test
    fun networkFailureBeforeCommitIsRetriedWithoutLoss() = runTest {
        val a = newVault()
        a.sync()
        a.add("entry")
        remote.fail("update", RemoteException(RemoteErrorCode.NETWORK))
        val r = a.sync()
        assertEquals(SyncResult.Status.UPLOADED, r.status)
        assertEquals(1, a.sleeps.size)
        assertTrue(a.sleeps[0] in 500L..1_000L)
        assertEquals(setOf("entry"), remoteTitles())
        assertFalse(a.state.load().dirty)
    }

    @Test
    fun responseLostAfterCommitIsIdempotentOnRetry() = runTest {
        val a = newVault()
        a.sync()
        a.add("entry")
        remote.failuresAfterCommit.addLast(RemoteException(RemoteErrorCode.NETWORK))
        val revisionsBefore = remote.revisions.size
        val r = a.sync()
        assertEquals(SyncResult.Status.DOWNLOADED, r.status) // the retry finds its own upload and adopts it
        assertEquals(revisionsBefore + 1, remote.revisions.size) // no duplicate upload
        assertEquals(setOf("entry"), remoteTitles())
        assertEquals(setOf("entry"), a.titles())
        assertFalse(a.state.load().dirty)
    }

    @Test
    fun offlineKeepsDirtyAndReportsNetwork() = runTest {
        val a = newVault()
        a.add("offline")
        repeat(5) { remote.fail("getMetadata", RemoteException(RemoteErrorCode.NETWORK)) }
        val r = a.sync()
        assertEquals(SyncResult.Status.FAILED, r.status)
        assertEquals("NETWORK", r.error)
        assertEquals(4, a.sleeps.size)
        assertTrue(a.state.load().dirty)
        assertEquals("NETWORK", a.state.load().lastError)
        assertNull(remote.head)
        assertEquals(setOf("offline"), a.titles())
    }

    @Test
    fun rollbackIsWarnedButMerged() = runTest {
        val a = newVault()
        a.add("one")
        a.sync()
        val oldRevision = remote.head!!.id
        a.add("two")
        a.sync()
        remote.rollbackTo(oldRevision)
        val r = a.sync()
        assertTrue(r.rollbackWarning)
        assertTrue(a.state.load().rollbackWarning)
        assertEquals(SyncResult.Status.UPLOADED, r.status)
        assertEquals(setOf("one", "two"), remoteTitles())
    }

    @Test
    fun authRequiredIsSurfacedWithoutRetry() = runTest {
        val a = newVault()
        remote.fail("getMetadata", RemoteException(RemoteErrorCode.AUTH_REQUIRED, 401))
        val r = a.sync()
        assertEquals(SyncResult.Status.FAILED, r.status)
        assertEquals("AUTH_REQUIRED", r.error)
        assertTrue(a.sleeps.isEmpty())
        assertEquals("AUTH_REQUIRED", a.state.load().lastError)
        assertFalse(remote.calls.contains("create"))
    }

    @Test
    fun rateLimitedUsesExponentialBackoffWithJitter() = runTest {
        val a = newVault()
        repeat(3) { remote.fail("getMetadata", RemoteException(RemoteErrorCode.RATE_LIMITED, 429)) }
        val r = a.sync()
        assertEquals(SyncResult.Status.CREATED, r.status)
        assertEquals(3, a.sleeps.size)
        listOf(1_000L, 2_000L, 4_000L).forEachIndexed { i, base -> assertTrue("${a.sleeps[i]} for $base", a.sleeps[i] in base / 2..base) }
    }

    @Test
    fun backoffIsCappedAndHonoursRetryAfter() {
        val e = SyncEngine(remote, FakeLocal, InMemorySyncStateStore(), random = Random(1))
        repeat(20) { attempt -> assertTrue(e.backoffMs(attempt) <= SyncEngine.MAX_BACKOFF_MS) }
        assertTrue(e.backoffMs(10) >= SyncEngine.MAX_BACKOFF_MS / 2)
        assertEquals(5_000L, e.backoffMs(0, retryAfterMs = 5_000))
        assertEquals(SyncEngine.MAX_BACKOFF_MS, e.backoffMs(0, retryAfterMs = 600_000))
    }

    @Test
    fun endlessInterleavingStopsAfterFiveRounds() = runTest {
        val a = newVault()
        a.sync()
        val b = cloneOf(a, "devB")
        a.add("mine")
        var n = 0
        remote.beforeUpdate = {
            b.add("other-${n++}")
            remote.externalWrite(b.vault.exportForUpload().container)
        }
        val r = a.sync()
        assertEquals(SyncResult.Status.FAILED, r.status)
        assertEquals(SyncEngine.CONFLICT_RETRY_EXHAUSTED, r.error)
        assertEquals(5, r.rounds)
        assertTrue("local data kept", a.titles().contains("mine"))
        assertTrue(a.state.load().dirty)
    }

    @Test
    fun tamperedRemoteFailsClosedWithoutUploading() = runTest {
        val a = newVault()
        a.add("safe")
        a.sync()
        remote.externalWrite("""{"tampered":true}""")
        remote.calls.clear()
        val r = a.sync()
        assertEquals(SyncResult.Status.FAILED, r.status)
        assertEquals("INTEGRITY_ERROR", r.error)
        assertFalse(remote.calls.contains("update"))
        assertFalse(remote.calls.contains("create"))
        assertEquals(setOf("safe"), a.titles())
    }

    @Test
    fun otherVaultOnDriveIsRejected() = runTest {
        val a = newVault()
        a.add("mine")
        val other = Device("devX").also { it.vault.create(MASTER) {} }
        other.add("foreign")
        remote.externalWrite(other.vault.exportForUpload().container)
        val r = a.sync()
        assertEquals("VAULT_MISMATCH", r.error)
        assertEquals(setOf("foreign"), remoteTitles())
        assertEquals(setOf("mine"), a.titles())
    }

    @Test
    fun localChangeDuringUploadKeepsDirty() = runTest {
        val a = newVault()
        a.sync()
        a.add("first")
        remote.beforeUpdate = { a.add("typed-while-uploading") }
        val r = a.sync()
        assertEquals(SyncResult.Status.UPLOADED, r.status)
        assertTrue("change made after export must stay pending", a.state.load().dirty)
        remote.beforeUpdate = null
        a.sync()
        assertEquals(setOf("first", "typed-while-uploading"), remoteTitles())
    }

    @Test
    fun intermediateRevisionSelection() {
        val revs = listOf("r1", "r2", "r3", "r4").map { RevisionInfo(it) }
        assertEquals(listOf("r2", "r3"), SyncEngine.intermediateRevisions(revs, "r1", "r4").map { it.id })
        assertEquals(emptyList<String>(), SyncEngine.intermediateRevisions(revs, "r3", "r4").map { it.id })
        // base purged: merge everything before ours (idempotent)
        assertEquals(listOf("r1", "r2", "r3"), SyncEngine.intermediateRevisions(revs, "gone", "r4").map { it.id })
        // ours not listed yet: everything after base
        assertEquals(listOf("r3", "r4"), SyncEngine.intermediateRevisions(revs, "r2", "unknown").map { it.id })
    }

    @Test
    fun createdVaultStartsDirtyAndStateResetsForOtherVault() = runTest {
        val a = newVault()
        assertTrue(a.state.load().dirty)
        assertNotNull(a.state.load().vaultId)
    }

    // ------------------------------------------------------------------ ADR-013: newer keys elsewhere

    /** A and B in sync; then B changes the master password and syncs (publishes keyring + 1). */
    private suspend fun passwordChangedOnB(): Pair<Device, Device> {
        val a = newVault()
        a.add("shared")
        a.sync()
        val b = cloneOf(a, "devB")
        b.vault.changeMasterPassword(MASTER, NEW_MASTER)
        b.add("from-B")
        assertEquals(SyncResult.Status.UPLOADED, b.sync().status)
        return a to b
    }

    @Test
    fun newerRemoteKeysStopSyncWithoutUploadingOrAdopting() = runTest {
        val (a, _) = passwordChangedOnB()
        a.add("A-offline")
        remote.calls.clear()
        val revisionsBefore = remote.revisions.size
        val r = a.sync()
        assertEquals(SyncResult.Status.FAILED, r.status)
        assertEquals(CoreException.KEYRING_CHANGED, r.error)
        assertEquals("remote container kept for adoption", remote.head!!.content, r.keyringChangedContainer)
        assertFalse(remote.calls.contains("update"))
        assertEquals(revisionsBefore, remote.revisions.size)
        assertEquals(CoreException.KEYRING_CHANGED, a.state.load().lastError)
        assertTrue(a.state.load().dirty)
        assertTrue("nothing adopted silently", a.titles().contains("A-offline") && !a.titles().contains("from-B"))
        assertTrue(a.sleeps.isEmpty())
        assertFalse(r.toString().contains("vaultId"))
    }

    @Test
    fun adoptingWithTheNewPasswordResumesSync() = runTest {
        val (a, _) = passwordChangedOnB()
        a.add("A-offline")
        val container = a.sync().keyringChangedContainer!!
        try {
            a.vault.adoptRemoteKeys(container, MASTER) // old password does not open the new keys
            fail("expected INVALID_CREDENTIALS")
        } catch (e: CoreException) {
            assertEquals(CoreException.INVALID_CREDENTIALS, e.code)
        }
        val adopted = a.vault.adoptRemoteKeys(container, NEW_MASTER)
        assertTrue(adopted.report.keyringAdopted)
        // Audit ALTA-1: a master password change also rotates the data key (old password + old copy read nothing new).
        assertTrue("password change rotates the DEK", adopted.dataKeyChanged)
        assertTrue(a.state.load().dirty)
        val r = a.sync()
        assertEquals(SyncResult.Status.UPLOADED, r.status)
        assertEquals(setOf("shared", "from-B", "A-offline"), remoteTitles())
        a.vault.lock()
        a.vault.unlockWithPassword(NEW_MASTER) // the local container now uses the new keys
        assertEquals(setOf("shared", "from-B", "A-offline"), a.titles())
    }

    @Test
    fun dataKeyRotationElsewhereRequiresReauthenticationAndChangesTheDek() = runTest {
        val a = newVault()
        a.add("x")
        a.sync()
        val b = cloneOf(a, "devB")
        val newRecovery = b.vault.rotateDataKey(MASTER)
        assertEquals("ROT1-ROT2-ROT3", newRecovery)
        b.sync()
        var dekChanged = 0
        a.vault.addDataKeyChangedListener { dekChanged++ }
        val r = a.sync()
        assertEquals(CoreException.KEYRING_CHANGED, r.error)
        val adopted = a.vault.adoptRemoteKeys(r.keyringChangedContainer!!, MASTER)
        assertTrue(adopted.dataKeyChanged)
        assertEquals(1, dekChanged)
        assertEquals(FakeCoreBridge.keyringOf(remote.head!!.content), FakeCoreBridge.keyringOf(a.storage.read()!!))
        val after = a.sync()
        assertTrue("sync resumes after adoption: ${after.status}", after.status != SyncResult.Status.FAILED)
    }

    @Test
    fun weakerKdfOnAdoptionIsReported() = runTest {
        val (a, _) = passwordChangedOnB()
        val container = a.sync().keyringChangedContainer!!
        val adopted = a.vault.adoptRemoteKeys(FakeCoreBridge.withWeakKdf(container), NEW_MASTER)
        assertTrue(adopted.report.kdfWeakened)
    }

    @Test
    fun localKeyChangeIsUploadedNotOverwritten() = runTest {
        val a = newVault()
        a.sync()
        a.vault.changeMasterPassword(MASTER, NEW_MASTER)
        val r = a.sync()
        assertEquals(SyncResult.Status.UPLOADED, r.status)
        assertEquals(FakeCoreBridge.keyringOf(a.storage.read()!!), FakeCoreBridge.keyringOf(remote.head!!.content))
    }

    private object FakeLocal : SyncLocal {
        override suspend fun mergeRemoteAndPersist(remoteContainer: String) = throw UnsupportedOperationException()
        override suspend fun exportForUpload() = throw UnsupportedOperationException()
        override fun changeSeq() = 0L
    }
}
