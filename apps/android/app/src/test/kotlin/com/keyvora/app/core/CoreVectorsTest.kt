package com.keyvora.app.core

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.util.Base64

/**
 * Cross-platform vectors (packages/shared-models/test-vectors/vault-v1.json) through the REAL core.
 * Runs only when the UniFFI source set is active (core-generated present) AND a host build of libkeyvora_ffi is
 * loadable by JNA (`-Djna.library.path`, set by Gradle to core-generated/host). Otherwise it is skipped, unless
 * `-Pkeyvora.requireHostCore=true` makes a missing host library / vectors file a failure (CI).
 */
class CoreVectorsTest {
    private lateinit var core: CoreBridge
    private lateinit var vectors: JSONObject
    private val device = "kotlin-vectors"

    @Before
    fun setUp() {
        val require = System.getProperty("keyvora.requireHostCore") == "true"
        core = CoreBridgeFactory.create()
        if (!core.isAvailable) skip("UniFFI source set inactive (no core-generated bindings)")
        val file = File(System.getProperty("keyvora.vectors") ?: "missing")
        if (!file.isFile) {
            if (require) throw AssertionError("vectors not found: $file")
            skip("vectors file not found: $file")
        }
        vectors = JSONObject(file.readText())
        try {
            core.defaultKdfParams()
        } catch (e: CoreException) {
            if (e.code != CoreException.CORE_NOT_BUILT || require) throw e
            skip(
                "host libkeyvora_ffi not loadable by JNA on this JVM (${e.cause?.javaClass?.simpleName}); " +
                    "put a host build in apps/android/core-generated/host to run the vectors",
            )
        }
    }

    private fun skip(reason: String) {
        System.err.println("CoreVectorsTest skipped: $reason")
        assumeTrue(reason, false)
    }

    private fun vault() = vectors.getJSONObject("vault")

    private fun checkEntries(s: VaultSession) {
        val expected = vault().getJSONArray("expectedEntries")
        val actual = s.listEntries().map { s.getEntry(it.id) }.sortedBy { it.title }
        val exp = (0 until expected.length()).map { expected.getJSONObject(it) }.sortedBy { it.getString("title") }
        assertEquals(exp.size, actual.size)
        exp.zip(actual).forEach { (e, a) ->
            assertEquals(e.getString("title"), a.title)
            assertEquals(e.getString("username"), a.username)
            assertEquals(e.getString("password"), a.password)
            assertEquals(e.getString("notes"), a.notes)
            val urls = e.getJSONArray("urls")
            assertEquals((0 until urls.length()).map { urls.getString(it) }, a.urls)
        }
    }

    @Test
    fun unlockWithPassword() {
        val s = core.unlockWithPassword(vault().getString("container"), vault().getString("masterPassword"), device)
        try {
            checkEntries(s)
        } finally {
            s.lock()
        }
    }

    @Test
    fun unlockWithNfdVariantOfPassword() {
        val s = core.unlockWithPassword(vault().getString("container"), vault().getString("masterPasswordNfdVariant"), device)
        try {
            checkEntries(s)
        } finally {
            s.lock()
        }
    }

    @Test
    fun unlockWithRecoveryKey() {
        val s = core.unlockWithRecoveryKey(vault().getString("container"), vault().getString("recoveryKey"), device)
        try {
            checkEntries(s)
        } finally {
            s.lock()
        }
    }

    @Test
    fun openWithDataKeyAndLockSemantics() {
        val dek = Base64.getDecoder().decode(vault().getString("dataKeyB64"))
        val s = core.openWithDataKey(vault().getString("container"), dek, device)
        checkEntries(s)
        s.lock()
        try {
            s.listEntries()
            throw AssertionError("expected LOCKED")
        } catch (e: CoreException) {
            assertEquals(CoreException.LOCKED, e.code)
        }
    }

    @Test
    fun wrongPasswordIsInvalidCredentials() {
        try {
            core.unlockWithPassword(vault().getString("container"), "not the password", device)
            throw AssertionError("expected INVALID_CREDENTIALS")
        } catch (e: CoreException) {
            assertEquals(CoreException.INVALID_CREDENTIALS, e.code)
        }
    }

    @Test
    fun originMatchingVectors() {
        val arr = vectors.getJSONArray("originMatching")
        for (i in 0 until arr.length()) {
            val v = arr.getJSONObject(i)
            assertEquals(
                "${v.getString("entryUrl")} vs ${v.getString("pageUrl")}",
                MatchLevel.fromWire(v.getString("expected")),
                core.matchLevel(v.getString("entryUrl"), v.getString("pageUrl")),
            )
        }
    }
}
