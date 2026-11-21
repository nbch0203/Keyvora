package com.keyvora.app.core

import uniffi.keyvora_ffi.FfiConflict
import uniffi.keyvora_ffi.FfiCredentialMatch
import uniffi.keyvora_ffi.FfiEntry
import uniffi.keyvora_ffi.FfiEntryInput
import uniffi.keyvora_ffi.FfiEntrySummary
import uniffi.keyvora_ffi.FfiGeneratorOptions
import uniffi.keyvora_ffi.FfiHistoryItem
import uniffi.keyvora_ffi.FfiKdfParams
import uniffi.keyvora_ffi.FfiMergeReport
import uniffi.keyvora_ffi.KeyvoraException
import uniffi.keyvora_ffi.VaultHandle

// Thin mapping layer over the UniFFI-generated API (packages/bindings-uniffi/src/lib.rs). No logic lives here.
// Top-level generated functions are called fully qualified to avoid clashing with the bridge's own member names.

internal object UniffiCoreBridge : CoreBridge {
    override val isAvailable: Boolean = true

    override fun create(master: String, params: KdfParams, deviceId: String, nowMs: Long): VaultSession =
        ffi { UniffiVaultSession(VaultHandle.create(master, params.toFfi(), deviceId, nowMs)) }

    override fun unlockWithPassword(container: String, master: String, deviceId: String): VaultSession =
        ffi { UniffiVaultSession(VaultHandle.unlockWithPassword(container, master, deviceId)) }

    override fun unlockWithRecoveryKey(container: String, recoveryKey: String, deviceId: String): VaultSession =
        ffi { UniffiVaultSession(VaultHandle.unlockWithRecoveryKey(container, recoveryKey, deviceId)) }

    override fun openWithDataKey(container: String, dek: ByteArray, deviceId: String): VaultSession =
        ffi { UniffiVaultSession(VaultHandle.openWithDataKey(container, dek, deviceId)) }

    override fun generatePassword(options: GeneratorOptions): String =
        ffi { uniffi.keyvora_ffi.generatePassword(options.toFfi()) }

    override fun passwordEntropyBits(options: GeneratorOptions): Double =
        ffi { uniffi.keyvora_ffi.passwordEntropyBits(options.toFfi()) }

    override fun defaultGeneratorOptions(): GeneratorOptions =
        ffi { uniffi.keyvora_ffi.defaultGeneratorOptions().toDomain() }

    override fun defaultKdfParams(): KdfParams = ffi { uniffi.keyvora_ffi.defaultKdfParams().toDomain() }

    override fun matchLevel(entryUrl: String, pageUrl: String): MatchLevel =
        ffi { MatchLevel.fromWire(uniffi.keyvora_ffi.matchLevel(entryUrl, pageUrl)) }

    override fun pageOrigin(pageUrl: String): String? = ffi { uniffi.keyvora_ffi.pageOrigin(pageUrl) }
}

internal class UniffiVaultSession(private val handle: VaultHandle) : VaultSession {
    @Volatile
    private var closed = false

    private inline fun <T> h(block: (VaultHandle) -> T): T {
        if (closed) throw CoreException(CoreException.LOCKED)
        return ffi { block(handle) }
    }

    override fun takeRecoveryKey(): String? = h { it.takeRecoveryKey() }
    override fun exportContainer(): String = h { it.exportContainer() }
    override fun vaultId(): String = h { it.vaultId() }
    override fun revision(): Long = h { it.revision().toLong() }
    override fun isDirty(): Boolean = h { it.isDirty() }
    override fun isLocked(): Boolean = closed || ffi { handle.isLocked() }
    override fun listEntries(): List<EntrySummary> = h { it.listEntries().map { s -> s.toDomain() } }
    override fun search(query: String): List<EntrySummary> = h { it.search(query).map { s -> s.toDomain() } }
    override fun getEntry(id: String): Entry = h { it.getEntry(id).toDomain() }
    override fun createEntry(input: EntryInput, nowMs: Long): Entry = h { it.createEntry(input.toFfi(), nowMs).toDomain() }
    override fun updateEntry(id: String, input: EntryInput, nowMs: Long): Entry =
        h { it.updateEntry(id, input.toFfi(), nowMs).toDomain() }

    override fun deleteEntry(id: String, nowMs: Long) = h { it.deleteEntry(id, nowMs) }
    override fun resolveConflict(id: String, choice: Int, nowMs: Long) = h { it.resolveConflict(id, choice, nowMs) }
    override fun findMatches(pageUrl: String): List<CredentialMatch> = h { it.findMatches(pageUrl).map { m -> m.toDomain() } }
    override fun findAppMatches(packageName: String): List<CredentialMatch> =
        h { it.findAppMatches(packageName).map { m -> m.toDomain() } }

    override fun changeMasterPassword(current: String, next: String, params: KdfParams, nowMs: Long) =
        h { it.changeMasterPassword(current, next, params.toFfi(), nowMs) }

    override fun resetMasterPasswordWithRecovery(recoveryKey: String, next: String, params: KdfParams, nowMs: Long) =
        h { it.resetMasterPasswordWithRecovery(recoveryKey, next, params.toFfi(), nowMs) }

    override fun rotateRecoveryKey(current: String) = h { it.rotateRecoveryKey(current) }
    override fun mergeRemote(remoteContainer: String): MergeReport = h { it.mergeRemote(remoteContainer).toDomain() }
    override fun adoptRemoteKeys(remoteContainer: String, master: String): MergeReport =
        h { it.adoptRemoteKeys(remoteContainer, master).toDomain() }

    override fun rotateDataKey(current: String) = h { it.rotateDataKey(current) }
    override fun passwordKdfParams(): KdfParams = h { it.passwordKdfParams().toDomain() }
    override fun previewContainer(container: String): List<EntrySummary> =
        h { it.previewContainer(container).map { s -> s.toDomain() } }
    override fun restoreEntriesFrom(container: String, ids: List<String>, nowMs: Long): List<Entry> =
        h { it.restoreEntriesFrom(container, ids, nowMs).map { e -> e.toDomain() } }

    override fun exportDataKey(): ByteArray = h { it.exportDataKey() }

    override fun lock() {
        if (closed) return
        closed = true
        try {
            handle.lock()
        } catch (_: Throwable) {
            // Rust lock() cannot fail; nothing to report.
        } finally {
            handle.close()
        }
    }
}

private inline fun <T> ffi(block: () -> T): T = try {
    block()
} catch (e: KeyvoraException) {
    throw e.toCore()
} catch (e: LinkageError) {
    // libkeyvora_ffi.so missing for this ABI, or JNA could not load it.
    throw CoreException(CoreException.CORE_NOT_BUILT, cause = e)
}

private fun KeyvoraException.toCore(): CoreException = when (this) {
    is KeyvoraException.InvalidFormat -> CoreException(CoreException.INVALID_FORMAT, detail)
    is KeyvoraException.UnsupportedVersion -> CoreException(CoreException.UNSUPPORTED_VERSION)
    is KeyvoraException.ParamsOutOfBounds -> CoreException(CoreException.PARAMS_OUT_OF_BOUNDS)
    is KeyvoraException.InvalidCredentials -> CoreException(CoreException.INVALID_CREDENTIALS)
    is KeyvoraException.InvalidRecoveryKey -> CoreException(CoreException.INVALID_RECOVERY_KEY)
    is KeyvoraException.IntegrityException -> CoreException(CoreException.INTEGRITY_ERROR) // UniFFI renames *Error variants
    is KeyvoraException.VaultMismatch -> CoreException(CoreException.VAULT_MISMATCH)
    is KeyvoraException.KeyringChanged -> CoreException(CoreException.KEYRING_CHANGED)
    is KeyvoraException.NotFound -> CoreException(CoreException.NOT_FOUND)
    is KeyvoraException.Validation -> CoreException(CoreException.VALIDATION, field)
    is KeyvoraException.Locked -> CoreException(CoreException.LOCKED)
    is KeyvoraException.Crypto -> CoreException(CoreException.CRYPTO)
}

private fun KdfParams.toFfi() = FfiKdfParams(memoryKib.toUInt(), iterations.toUInt(), parallelism.toUInt())
private fun FfiKdfParams.toDomain() = KdfParams(memoryKib.toInt(), iterations.toInt(), parallelism.toInt())

private fun GeneratorOptions.toFfi() =
    FfiGeneratorOptions(length.toUInt(), lowercase, uppercase, digits, symbols, excludeAmbiguous, requireEachClass)

private fun FfiGeneratorOptions.toDomain() =
    GeneratorOptions(length.toInt(), lowercase, uppercase, digits, symbols, excludeAmbiguous, requireEachClass)

private fun EntryInput.toFfi() = FfiEntryInput(title, username, password, urls, notes)

private fun FfiEntrySummary.toDomain() = EntrySummary(id, title, username, urls, updatedAt, hasConflicts)

private fun FfiHistoryItem.toDomain() = HistoryItem(password, retiredAt)

private fun FfiConflict.toDomain() = ConflictSnapshot(kind, title, username, password, urls, notes, updatedAt, updatedBy)

private fun FfiEntry.toDomain() = Entry(
    id, title, username, password, urls, notes, createdAt, updatedAt, updatedBy,
    passwordHistory.map { it.toDomain() }, conflicts.map { it.toDomain() },
)

private fun FfiCredentialMatch.toDomain() =
    CredentialMatch(entry.toDomain(), MatchLevel.fromWire(level), matchedUrl, pageHost, pageIsIdn)

private fun FfiMergeReport.toDomain() = MergeReport(
    remoteRevision.toLong(), adoptedRemote, needsUpload, added.toInt(), updated.toInt(), removed.toInt(),
    newConflicts, keyringAdopted, keyringConflict, kdfWeakened, recoveryKeyChanged,
)
