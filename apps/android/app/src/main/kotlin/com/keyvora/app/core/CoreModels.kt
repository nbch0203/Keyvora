package com.keyvora.app.core

// Kotlin domain types mirroring docs/CONTRACTS.md §1.2/§2/§3. They are plain data holders: every rule (crypto,
// format, merge, origin matching) lives in the Rust core and is reached only through [CoreBridge].
// toString() is overridden wherever a secret is held so that an accidental log/print never shows it.

data class KdfParams(val memoryKib: Int, val iterations: Int, val parallelism: Int)

data class EntryInput(
    val title: String,
    val username: String,
    val password: String,
    val urls: List<String>,
    val notes: String,
) {
    override fun toString() = "EntryInput(title=<redacted>, urls=${urls.size})"
}

data class EntrySummary(
    val id: String,
    val title: String,
    val username: String,
    val urls: List<String>,
    val updatedAt: String,
    val hasConflicts: Boolean,
) {
    override fun toString() = "EntrySummary(id=$id)"
}

data class HistoryItem(val password: String, val retiredAt: String) {
    override fun toString() = "HistoryItem(retiredAt=$retiredAt)"
}

data class ConflictSnapshot(
    /** "edit" | "deletion" */
    val kind: String,
    val title: String,
    val username: String,
    val password: String,
    val urls: List<String>,
    val notes: String,
    val updatedAt: String,
    val updatedBy: String,
) {
    val isDeletion: Boolean get() = kind == "deletion"
    override fun toString() = "ConflictSnapshot(kind=$kind, updatedAt=$updatedAt)"
}

data class Entry(
    val id: String,
    val title: String,
    val username: String,
    val password: String,
    val urls: List<String>,
    val notes: String,
    val createdAt: String,
    val updatedAt: String,
    val updatedBy: String,
    val passwordHistory: List<HistoryItem>,
    val conflicts: List<ConflictSnapshot>,
) {
    fun toInput() = EntryInput(title, username, password, urls, notes)
    override fun toString() = "Entry(id=$id)"
}

enum class MatchLevel(val wire: String) {
    EXACT("exact"),
    SAME_SITE("sameSite"),
    NONE("none");

    companion object {
        fun fromWire(value: String): MatchLevel = entries.firstOrNull { it.wire == value } ?: NONE
    }
}

data class CredentialMatch(
    val entry: EntrySummary,
    val level: MatchLevel,
    val matchedUrl: String,
    /** Real page host (punycode when IDN) or the Android package for app matches. */
    val pageHost: String,
    val pageIsIdn: Boolean,
)

data class MergeReport(
    val remoteRevision: Long,
    val adoptedRemote: Boolean,
    val needsUpload: Boolean,
    val added: Int,
    val updated: Int,
    val removed: Int,
    val newConflicts: List<String>,
    val keyringAdopted: Boolean,
    val keyringConflict: Boolean,
    /** Adopted remote keys use weaker Argon2id parameters than before / than the defaults (warn the user). */
    val kdfWeakened: Boolean = false,
    /** The adopted keys carry another recovery key: the one shown earlier on this device no longer works (QA-DEF-004). */
    val recoveryKeyChanged: Boolean = false,
)

data class GeneratorOptions(
    val length: Int = 20,
    val lowercase: Boolean = true,
    val uppercase: Boolean = true,
    val digits: Boolean = true,
    val symbols: Boolean = true,
    val excludeAmbiguous: Boolean = false,
    val requireEachClass: Boolean = true,
)

/**
 * Error raised by the core (codes of CONTRACTS §1.2) or by the bridge itself ([CORE_NOT_BUILT]).
 * [detail] only ever carries non-secret information (field name or static description).
 */
class CoreException(val code: String, val detail: String? = null, cause: Throwable? = null) : Exception(code, cause) {
    companion object {
        const val INVALID_FORMAT = "INVALID_FORMAT"
        const val UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
        const val PARAMS_OUT_OF_BOUNDS = "PARAMS_OUT_OF_BOUNDS"
        const val INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
        const val INVALID_RECOVERY_KEY = "INVALID_RECOVERY_KEY"
        const val INTEGRITY_ERROR = "INTEGRITY_ERROR"
        const val VAULT_MISMATCH = "VAULT_MISMATCH"

        /** Remote container has newer keys (password changed / DEK rotated elsewhere): ask for the master password
         *  and call `adoptRemoteKeys` (ADR-013). Never adopted silently. */
        const val KEYRING_CHANGED = "KEYRING_CHANGED"
        const val NOT_FOUND = "NOT_FOUND"
        const val VALIDATION = "VALIDATION"
        const val LOCKED = "LOCKED"
        const val CRYPTO = "CRYPTO"

        /** The native core / generated bindings are not part of this build. */
        const val CORE_NOT_BUILT = "CORE_NOT_BUILT"

        val CONTRACT_CODES = listOf(
            INVALID_FORMAT, UNSUPPORTED_VERSION, PARAMS_OUT_OF_BOUNDS, INVALID_CREDENTIALS, INVALID_RECOVERY_KEY,
            INTEGRITY_ERROR, VAULT_MISMATCH, KEYRING_CHANGED, NOT_FOUND, VALIDATION, LOCKED, CRYPTO,
        )
    }
}
