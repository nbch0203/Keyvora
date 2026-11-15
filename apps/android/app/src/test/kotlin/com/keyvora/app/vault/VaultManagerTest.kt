package com.keyvora.app.vault

import com.keyvora.app.core.CoreException
import com.keyvora.app.core.EntryInput
import com.keyvora.app.sync.InMemorySyncStateStore
import com.keyvora.app.testing.FakeCoreBridge
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class VaultManagerTest {
    private val storage = InMemoryContainerStorage()
    private val state = InMemorySyncStateStore()
    private val vm = VaultManager(
        FakeCoreBridge(), storage, { "dev1" }, state, CoroutineScope(Dispatchers.Unconfined),
        clock = { 1_000L }, worker = Dispatchers.Unconfined,
    )

    private suspend fun expectCode(code: String, block: suspend () -> Unit) {
        try {
            block()
            fail("expected $code")
        } catch (e: CoreException) {
            assertEquals(code, e.code)
        }
    }

    @Test
    fun createShowsRecoveryKeyBeforeUnlockAndPersists() = runTest {
        assertEquals(VaultManager.Status.NO_VAULT, vm.status.value)
        var statusWhenKeyDelivered: VaultManager.Status? = null
        vm.create("master-password") { statusWhenKeyDelivered = vm.status.value }
        assertEquals(VaultManager.Status.NO_VAULT, statusWhenKeyDelivered)
        assertEquals(VaultManager.Status.UNLOCKED, vm.status.value)
        assertTrue(storage.exists())
        assertTrue(state.load().dirty)
    }

    @Test
    fun mutationsAreExportedAndFlagSyncDirty() = runTest {
        vm.create("master-password") {}
        state.update { it.copy(dirty = false) }
        val before = storage.read()
        var notified = 0
        vm.addLocalChangeListener { notified++ }
        val seq = vm.changeSeq()
        vm.mutate { it.createEntry(EntryInput("GitHub", "alice", "pw", emptyList(), ""), 1) }
        assertNotEquals(before, storage.read())
        assertTrue(FakeCoreBridge.entryTitles(storage.read()!!).contains("GitHub"))
        assertTrue(state.load().dirty)
        assertEquals(1, notified)
        assertEquals(seq + 1, vm.changeSeq())
    }

    @Test
    fun lockWipesSessionAndRefusesAccess() = runTest {
        vm.create("master-password") {}
        var lockEvents = 0
        vm.addLockListener { lockEvents++ }
        vm.lock()
        assertEquals(VaultManager.Status.LOCKED, vm.status.value)
        assertEquals(1, lockEvents)
        expectCode(CoreException.LOCKED) { vm.listEntries("") }
        expectCode(CoreException.LOCKED) { vm.mutate { it.deleteEntry("x", 1) } }
        vm.lock() // idempotent
        assertEquals(1, lockEvents)
    }

    @Test
    fun unlockWithWrongPasswordStaysLocked() = runTest {
        vm.create("master-password") {}
        vm.lock()
        expectCode(CoreException.INVALID_CREDENTIALS) { vm.unlockWithPassword("wrong") }
        assertEquals(VaultManager.Status.LOCKED, vm.status.value)
        vm.unlockWithPassword("master-password")
        assertEquals(VaultManager.Status.UNLOCKED, vm.status.value)
    }

    @Test
    fun recoveryUnlockSetsNewMasterPassword() = runTest {
        vm.create("master-password") {}
        vm.lock()
        vm.unlockWithRecoveryKey("AAAA-BBBB-CCCC", "new-master-password")
        vm.lock()
        expectCode(CoreException.INVALID_CREDENTIALS) { vm.unlockWithPassword("master-password") }
        vm.unlockWithPassword("new-master-password")
        assertTrue(state.load().dirty)
    }

    @Test
    fun importOfAnotherVaultIsRejected() = runTest {
        val other = VaultManager(FakeCoreBridge(), InMemoryContainerStorage(), { "dev2" }, InMemorySyncStateStore(), CoroutineScope(Dispatchers.Unconfined), worker = Dispatchers.Unconfined)
        other.create("x-master-password") {}
        val foreign = other.exportBackup()
        vm.create("master-password") {}
        expectCode(CoreException.VAULT_MISMATCH) { vm.importMerge(foreign) }
    }

    @Test
    fun pendingImportCanBeDiscardedOnlyWhileLocked() = runTest {
        val src = VaultManager(FakeCoreBridge(), InMemoryContainerStorage(), { "dev2" }, InMemorySyncStateStore(), CoroutineScope(Dispatchers.Unconfined), worker = Dispatchers.Unconfined)
        src.create("x-master-password") {}
        vm.installContainer(src.exportBackup())
        assertEquals(VaultManager.Status.LOCKED, vm.status.value)
        vm.discardPendingImport()
        assertEquals(VaultManager.Status.NO_VAULT, vm.status.value)
        assertFalse(storage.exists())
    }

    @Test
    fun masterPasswordShorterThanTwelveIsRejectedByTheCore() = runTest {
        expectCode(CoreException.VALIDATION) { vm.create("elevenchars") {} }
        assertEquals(VaultManager.Status.NO_VAULT, vm.status.value)
        vm.create("twelve chars") {}
        assertEquals(VaultManager.Status.UNLOCKED, vm.status.value)
    }

    @Test
    fun dataKeyRotationReturnsNewRecoveryKeyAndNotifies() = runTest {
        vm.create("master-password") {}
        var notified = 0
        vm.addDataKeyChangedListener { notified++ }
        val before = vm.exportDataKey().toList()
        expectCode(CoreException.INVALID_CREDENTIALS) { vm.rotateDataKey("wrong password!") }
        assertEquals(0, notified)
        val rk = vm.rotateDataKey("master-password")
        assertEquals("ROT1-ROT2-ROT3", rk)
        assertEquals(1, notified)
        assertTrue(before != vm.exportDataKey().toList())
        assertTrue(state.load().dirty)
        vm.lock()
        vm.unlockWithPassword("master-password")
    }

    @Test
    fun previewUsesTheCoreAndFailsForOldDataKey() = runTest {
        vm.create("master-password") {}
        vm.mutate { it.createEntry(EntryInput("Old", "u", "p", emptyList(), ""), 1) }
        val backup = vm.exportBackup()
        assertEquals(listOf("Old"), vm.previewContainer(backup).map { it.title })
        vm.rotateDataKey("master-password")
        expectCode(CoreException.INVALID_CREDENTIALS) { vm.previewContainer(backup) }
    }

    @Test
    fun keyringAdoptionHolderAdoptsAndClears() = runTest {
        vm.create("master-password") {}
        val other = VaultManager(FakeCoreBridge(), InMemoryContainerStorage(vm.exportBackup()), { "dev2" }, InMemorySyncStateStore(), CoroutineScope(Dispatchers.Unconfined), worker = Dispatchers.Unconfined)
        other.unlockWithPassword("master-password")
        other.changeMasterPassword("master-password", "changed master password")
        val newer = other.exportBackup()
        expectCode(CoreException.KEYRING_CHANGED) { vm.importMerge(newer) }

        val holder = com.keyvora.app.sync.KeyringAdoption(vm)
        val adoptedFrom = mutableListOf<com.keyvora.app.sync.KeyringAdoption.Source>()
        holder.addAdoptedListener { adoptedFrom += it }
        holder.offer(com.keyvora.app.sync.KeyringAdoption.Source.IMPORT, newer)
        assertFalse(holder.pending.value.toString().contains("vaultId"))
        expectCode(CoreException.INVALID_CREDENTIALS) { holder.adopt("master-password") }
        assertTrue(holder.pending.value != null)
        holder.adopt("changed master password")
        assertEquals(null, holder.pending.value)
        assertEquals(listOf(com.keyvora.app.sync.KeyringAdoption.Source.IMPORT), adoptedFrom)
    }

    @Test
    fun stateOfAnotherVaultIsReset() = runTest {
        state.update { it.copy(vaultId = "some-other-vault", fileId = "F", lastSyncedHeadRevisionId = "H") }
        vm.create("master-password") {}
        vm.lock()
        state.update { it.copy(vaultId = "some-other-vault", fileId = "F") }
        vm.unlockWithPassword("master-password")
        assertEquals(null, state.load().fileId)
        assertTrue(state.load().dirty)
    }
}
