package com.keyvora.app.core

/**
 * Entry point to the shared Rust core (docs/CONTRACTS.md §3). Implemented by `UniffiCoreBridge` (src/uniffi) when
 * the generated bindings are present, or by `NoCoreBridge` (src/nocore), which throws `CORE_NOT_BUILT`.
 * Obtain it with `CoreBridgeFactory.create()`.
 *
 * Every function may throw [CoreException]. Calls that derive keys (create / unlock / password changes) run
 * Argon2id (~1 s): never call them on the main thread.
 */
interface CoreBridge {
    val isAvailable: Boolean

    fun create(master: String, params: KdfParams, deviceId: String, nowMs: Long): VaultSession
    fun unlockWithPassword(container: String, master: String, deviceId: String): VaultSession
    fun unlockWithRecoveryKey(container: String, recoveryKey: String, deviceId: String): VaultSession
    fun openWithDataKey(container: String, dek: ByteArray, deviceId: String): VaultSession

    fun generatePassword(options: GeneratorOptions): String
    fun passwordEntropyBits(options: GeneratorOptions): Double
    fun defaultGeneratorOptions(): GeneratorOptions
    fun defaultKdfParams(): KdfParams

    /** CONTRACTS §4. */
    fun matchLevel(entryUrl: String, pageUrl: String): MatchLevel

    /** Normalized `https://host[:port]` origin of a fillable page, or null if the page cannot be filled. */
    fun pageOrigin(pageUrl: String): String?
}

/**
 * An unlocked vault handle (Rust `VaultHandle`). Holds the DEK in native memory until [lock], after which every call
 * throws `CoreException(LOCKED)`. Callers must serialize mutations (see VaultManager).
 */
interface VaultSession {
    /** Recovery key produced by create/rotateRecoveryKey; returned only once. */
    fun takeRecoveryKey(): String?
    fun exportContainer(): String
    fun vaultId(): String
    fun revision(): Long
    fun isDirty(): Boolean
    fun isLocked(): Boolean
    fun listEntries(): List<EntrySummary>
    fun search(query: String): List<EntrySummary>
    fun getEntry(id: String): Entry
    fun createEntry(input: EntryInput, nowMs: Long): Entry
    fun updateEntry(id: String, input: EntryInput, nowMs: Long): Entry
    fun deleteEntry(id: String, nowMs: Long)

    /** [choice] < 0 keeps the current version; otherwise takes conflict number [choice]. */
    fun resolveConflict(id: String, choice: Int, nowMs: Long)
    fun findMatches(pageUrl: String): List<CredentialMatch>
    fun findAppMatches(packageName: String): List<CredentialMatch>
    fun changeMasterPassword(current: String, next: String, params: KdfParams)
    fun resetMasterPasswordWithRecovery(recoveryKey: String, next: String, params: KdfParams)

    /** Rotates the recovery key (requires the current master password); read the new one with [takeRecoveryKey]. */
    fun rotateRecoveryKey(current: String)
    /** Throws `KEYRING_CHANGED` when the remote keys are newer; never adopts them silently. */
    fun mergeRemote(remoteContainer: String): MergeReport

    /** Re-authenticates with the master password valid for [remoteContainer], adopts its keys and merges local data. */
    fun adoptRemoteKeys(remoteContainer: String, master: String): MergeReport

    /** New DEK + new password slot + new recovery key (read it with [takeRecoveryKey]). Protects future data only. */
    fun rotateDataKey(current: String)

    /** KDF parameters of the master-password slot. */
    fun passwordKdfParams(): KdfParams

    /** Entries of another container of this vault (restore UIs). */
    fun previewContainer(container: String): List<EntrySummary>
    fun restoreEntriesFrom(container: String, ids: List<String>, nowMs: Long): List<Entry>

    /** DEK copy for the biometric keystore wrap. Callers must zero it (`fill(0)`) as soon as possible. */
    fun exportDataKey(): ByteArray

    /** Wipes the DEK and releases the native handle. Idempotent. */
    fun lock()
}
