package com.keyvora.app.sync

import com.keyvora.app.vault.VaultManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Pending adoption of newer remote keys (ADR-013 / SECURITY_REVIEW M-2). Set when a merge (sync or import) fails with
 * KEYRING_CHANGED; the UI asks for the master password that opens that container and calls [adopt].
 * Holds only the encrypted container, in memory; cleared on lock (the next sync detects it again).
 */
class KeyringAdoption(private val vault: VaultManager) {
    enum class Source { SYNC, IMPORT }

    class Pending(val source: Source, val container: String) {
        override fun toString() = "Pending(source=$source)"
    }

    private val _pending = MutableStateFlow<Pending?>(null)
    val pending: StateFlow<Pending?> = _pending.asStateFlow()
    private val adoptedListeners = mutableListOf<(Source) -> Unit>()

    fun addAdoptedListener(l: (Source) -> Unit) { adoptedListeners += l }

    fun offer(source: Source, container: String) { _pending.value = Pending(source, container) }

    fun dismiss() { _pending.value = null }

    /** @throws com.keyvora.app.core.CoreException INVALID_CREDENTIALS if the password does not open the container. */
    suspend fun adopt(master: String): VaultManager.AdoptResult {
        val p = _pending.value ?: throw IllegalStateException("nothing to adopt")
        val result = vault.adoptRemoteKeys(p.container, master)
        _pending.value = null
        adoptedListeners.forEach { runCatching { it(p.source) } }
        return result
    }
}
