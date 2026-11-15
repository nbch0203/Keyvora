package com.keyvora.app.testing

import com.keyvora.app.core.CoreBridge
import com.keyvora.app.core.CoreException
import com.keyvora.app.core.CredentialMatch
import com.keyvora.app.core.Entry
import com.keyvora.app.core.EntryInput
import com.keyvora.app.core.EntrySummary
import com.keyvora.app.core.GeneratorOptions
import com.keyvora.app.core.KdfParams
import com.keyvora.app.core.MatchLevel
import com.keyvora.app.core.MergeReport
import com.keyvora.app.core.VaultSession
import org.json.JSONObject
import java.util.UUID

/**
 * TEST-ONLY stand-in for the Rust core. It is NOT a vault implementation: the "container" is plain JSON and the
 * merge is a simple deterministic union (per id, the record with the greater `updatedAt` wins; ties by content).
 * Keys are modelled just enough to exercise the Kotlin orchestration of ADR-013 (keyring revision, master password,
 * DEK id): newer remote keys → KEYRING_CHANGED; adoption requires the remote's master password.
 * Real crypto/merge/key-policy correctness is tested in Rust (packages/vault-core, packages/sync-core).
 */
class FakeCoreBridge : CoreBridge {
    override val isAvailable = true

    override fun create(master: String, params: KdfParams, deviceId: String, nowMs: Long): VaultSession {
        checkMaster(master)
        return FakeSession(
            Keys(UUID.randomUUID().toString(), master, newDek(), 1, weakKdf = false), deviceId, 0, sortedMapOf(),
            dirty = true, recoveryKey = RECOVERY,
        )
    }

    override fun unlockWithPassword(container: String, master: String, deviceId: String): VaultSession {
        val c = parse(container)
        if (c.keys.master != master) throw CoreException(CoreException.INVALID_CREDENTIALS)
        return FakeSession(c.keys, deviceId, c.revision, c.records, dirty = false)
    }

    override fun unlockWithRecoveryKey(container: String, recoveryKey: String, deviceId: String): VaultSession {
        val c = parse(container)
        if (recoveryKey != RECOVERY) throw CoreException(CoreException.INVALID_CREDENTIALS)
        return FakeSession(c.keys, deviceId, c.revision, c.records, dirty = false)
    }

    override fun openWithDataKey(container: String, dek: ByteArray, deviceId: String): VaultSession {
        val c = parse(container)
        if (String(dek) != c.keys.dek) throw CoreException(CoreException.INVALID_CREDENTIALS)
        return FakeSession(c.keys, deviceId, c.revision, c.records, dirty = false)
    }

    override fun generatePassword(options: GeneratorOptions) = "x".repeat(options.length)
    override fun passwordEntropyBits(options: GeneratorOptions) = options.length * 6.0
    override fun defaultGeneratorOptions() = GeneratorOptions()
    override fun defaultKdfParams() = STRONG
    override fun matchLevel(entryUrl: String, pageUrl: String) = if (entryUrl == pageUrl) MatchLevel.EXACT else MatchLevel.NONE
    override fun pageOrigin(pageUrl: String): String? = pageUrl

    data class Keys(val vaultId: String, val master: String, val dek: String, val keyring: Long, val weakKdf: Boolean)

    data class Rec(val title: String, val username: String, val password: String, val updatedAt: Long, val by: String, val deleted: Boolean) {
        fun json(): JSONObject = JSONObject().put("title", title).put("username", username).put("password", password)
            .put("updatedAt", updatedAt).put("by", by).put("deleted", deleted)

        companion object {
            fun of(o: JSONObject) = Rec(
                o.getString("title"), o.getString("username"), o.getString("password"),
                o.getLong("updatedAt"), o.getString("by"), o.getBoolean("deleted"),
            )
        }
    }

    class Parsed(val keys: Keys, val revision: Long, val records: java.util.SortedMap<String, Rec>)

    companion object {
        const val RECOVERY = "AAAA-BBBB-CCCC"
        val STRONG = KdfParams(65536, 3, 1)
        val WEAK = KdfParams(19456, 2, 1)

        private fun newDek() = UUID.randomUUID().toString()

        private fun checkMaster(m: String) {
            if (m.codePointCount(0, m.length) < 12) throw CoreException(CoreException.VALIDATION, "masterPassword")
        }

        fun parse(container: String): Parsed {
            val o = try {
                JSONObject(container)
            } catch (e: Exception) {
                throw CoreException(CoreException.INVALID_FORMAT)
            }
            if (o.optBoolean("tampered")) throw CoreException(CoreException.INTEGRITY_ERROR)
            val recs = sortedMapOf<String, Rec>()
            val entries = o.getJSONObject("entries")
            entries.keys().forEach { recs[it] = Rec.of(entries.getJSONObject(it)) }
            val keys = Keys(o.getString("vaultId"), o.getString("master"), o.getString("dek"), o.getLong("keyring"), o.optBoolean("weakKdf"))
            return Parsed(keys, o.getLong("revision"), recs)
        }

        fun entryTitles(container: String): Set<String> =
            parse(container).records.values.filter { !it.deleted }.map { it.title }.toSet()

        fun keyringOf(container: String): Long = parse(container).keys.keyring

        /** Test helper: same container but its password slot marked as using weak KDF parameters. */
        fun withWeakKdf(container: String): String = JSONObject(container).put("weakKdf", true).toString()

        private fun winner(a: Rec, b: Rec): Rec = when {
            a.updatedAt != b.updatedAt -> if (a.updatedAt > b.updatedAt) a else b
            else -> if (a.json().toString() >= b.json().toString()) a else b
        }

        private fun union(local: Map<String, Rec>, remote: Map<String, Rec>): java.util.SortedMap<String, Rec> {
            val merged = sortedMapOf<String, Rec>()
            (local.keys + remote.keys).forEach { id ->
                val l = local[id]
                val r = remote[id]
                merged[id] = when {
                    l == null -> r!!
                    r == null -> l
                    else -> winner(l, r)
                }
            }
            return merged
        }
    }

    class FakeSession(
        private var keys: Keys,
        private val deviceId: String,
        private var revision: Long,
        records: Map<String, Rec>,
        private var dirty: Boolean,
        private var recoveryKey: String? = null,
    ) : VaultSession {
        private val records = sortedMapOf<String, Rec>().apply { putAll(records) }
        private var locked = false
        private var counter = 0

        private fun check() {
            if (locked) throw CoreException(CoreException.LOCKED)
        }

        override fun takeRecoveryKey(): String? = recoveryKey.also { recoveryKey = null }

        override fun exportContainer(): String {
            check()
            if (dirty) revision++
            dirty = false
            val entries = JSONObject()
            records.forEach { (k, v) -> entries.put(k, v.json()) }
            return JSONObject().put("vaultId", keys.vaultId).put("master", keys.master).put("dek", keys.dek)
                .put("keyring", keys.keyring).put("weakKdf", keys.weakKdf)
                .put("revision", revision).put("entries", entries).toString()
        }

        override fun vaultId() = keys.vaultId.also { check() }
        override fun revision() = revision.also { check() }
        override fun isDirty() = dirty.also { check() }
        override fun isLocked() = locked

        private fun summary(id: String, r: Rec) = EntrySummary(id, r.title, r.username, emptyList(), r.updatedAt.toString(), false)

        override fun listEntries(): List<EntrySummary> {
            check()
            return records.filter { !it.value.deleted }.map { summary(it.key, it.value) }
        }

        override fun search(query: String) = listEntries().filter { it.title.contains(query, ignoreCase = true) }

        override fun getEntry(id: String): Entry {
            check()
            val r = records[id]?.takeIf { !it.deleted } ?: throw CoreException(CoreException.NOT_FOUND)
            return Entry(id, r.title, r.username, r.password, emptyList(), "", "0", r.updatedAt.toString(), r.by, emptyList(), emptyList())
        }

        override fun createEntry(input: EntryInput, nowMs: Long): Entry {
            check()
            if (input.title.isBlank()) throw CoreException(CoreException.VALIDATION, "title")
            val id = "$deviceId-${++counter}-$nowMs"
            records[id] = Rec(input.title, input.username, input.password, nowMs, deviceId, false)
            dirty = true
            return getEntry(id)
        }

        override fun updateEntry(id: String, input: EntryInput, nowMs: Long): Entry {
            check()
            if (records[id]?.deleted != false) throw CoreException(CoreException.NOT_FOUND)
            records[id] = Rec(input.title, input.username, input.password, nowMs, deviceId, false)
            dirty = true
            return getEntry(id)
        }

        override fun deleteEntry(id: String, nowMs: Long) {
            check()
            val r = records[id] ?: throw CoreException(CoreException.NOT_FOUND)
            records[id] = r.copy(updatedAt = nowMs, by = deviceId, deleted = true)
            dirty = true
        }

        override fun resolveConflict(id: String, choice: Int, nowMs: Long) = check()
        override fun findMatches(pageUrl: String): List<CredentialMatch> = emptyList()
        override fun findAppMatches(packageName: String): List<CredentialMatch> = emptyList()

        private fun requireMaster(current: String) {
            if (current != keys.master) throw CoreException(CoreException.INVALID_CREDENTIALS)
        }

        override fun changeMasterPassword(current: String, next: String, params: KdfParams) {
            check()
            requireMaster(current)
            checkMaster(next)
            keys = keys.copy(master = next, keyring = keys.keyring + 1, weakKdf = false)
            dirty = true
        }

        override fun resetMasterPasswordWithRecovery(recoveryKey: String, next: String, params: KdfParams) {
            check()
            if (recoveryKey != RECOVERY) throw CoreException(CoreException.INVALID_CREDENTIALS)
            checkMaster(next)
            keys = keys.copy(master = next, keyring = keys.keyring + 1)
            dirty = true
        }

        override fun rotateRecoveryKey(current: String) {
            check()
            requireMaster(current)
            recoveryKey = "NEW1-NEW2-NEW3"
            keys = keys.copy(keyring = keys.keyring + 1)
            dirty = true
        }

        override fun rotateDataKey(current: String) {
            check()
            requireMaster(current)
            keys = keys.copy(dek = newDek(), keyring = keys.keyring + 1)
            recoveryKey = "ROT1-ROT2-ROT3"
            dirty = true
        }

        override fun passwordKdfParams(): KdfParams = if (keys.weakKdf) WEAK else STRONG

        private fun mergeRecords(remote: Parsed, adoptKeys: Boolean, kdfWeakened: Boolean): MergeReport {
            val merged = union(records, remote.records)
            val added = merged.keys.count { it !in records }
            val updated = merged.count { (k, v) -> records[k] != null && records[k] != v }
            val adopted = merged == remote.records && remote.revision >= revision &&
                (adoptKeys || keys == remote.keys)
            records.clear()
            records.putAll(merged)
            if (adopted) {
                revision = remote.revision
                dirty = false
            } else {
                revision = maxOf(revision, remote.revision)
                dirty = true
            }
            return MergeReport(remote.revision, adopted, !adopted, added, updated, 0, emptyList(), adoptKeys, false, kdfWeakened)
        }

        override fun mergeRemote(remoteContainer: String): MergeReport {
            check()
            val remote = parse(remoteContainer)
            if (remote.keys.vaultId != keys.vaultId) throw CoreException(CoreException.VAULT_MISMATCH)
            if (remote.keys.keyring > keys.keyring) throw CoreException(CoreException.KEYRING_CHANGED)
            if (remote.keys.keyring == keys.keyring && remote.keys != keys) {
                // concurrent key changes: keep ours and publish them as newer (the other side re-authenticates once)
                keys = keys.copy(keyring = keys.keyring + 1)
            }
            return mergeRecords(remote, adoptKeys = false, kdfWeakened = false)
        }

        override fun adoptRemoteKeys(remoteContainer: String, master: String): MergeReport {
            check()
            val remote = parse(remoteContainer)
            if (remote.keys.master != master) throw CoreException(CoreException.INVALID_CREDENTIALS)
            if (remote.keys.vaultId != keys.vaultId) throw CoreException(CoreException.VAULT_MISMATCH)
            val weakened = remote.keys.weakKdf && !keys.weakKdf
            keys = remote.keys
            return mergeRecords(remote, adoptKeys = true, kdfWeakened = weakened)
        }

        override fun previewContainer(container: String): List<EntrySummary> {
            check()
            val old = parse(container)
            if (old.keys.vaultId != keys.vaultId) throw CoreException(CoreException.VAULT_MISMATCH)
            if (old.keys.dek != keys.dek) throw CoreException(CoreException.INVALID_CREDENTIALS)
            return old.records.filter { !it.value.deleted }.map { summary(it.key, it.value) }
        }

        override fun restoreEntriesFrom(container: String, ids: List<String>, nowMs: Long): List<Entry> {
            val old = parse(container)
            return ids.map { id ->
                val r = old.records[id] ?: throw CoreException(CoreException.NOT_FOUND)
                createEntry(EntryInput(r.title, r.username, r.password, emptyList(), ""), nowMs)
            }
        }

        override fun exportDataKey(): ByteArray = keys.dek.toByteArray().also { check() }

        override fun lock() {
            locked = true
            records.clear()
        }
    }
}
