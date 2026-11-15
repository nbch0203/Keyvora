package com.keyvora.app.security

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * T13: no android.util.Log / println call in the app sources may mention passwords, tokens, keys or the master
 * password. Scans app/src/main plus both core-bridge source sets.
 */
class NoSecretLogsTest {
    private val logCall = Regex("""\b(Log\.(v|d|i|w|e|wtf)|println|print|System\.(out|err))\s*\(""")
    private val suspicious = Regex("password|passwd|token|dek|secret|master|recovery|container|cipher", RegexOption.IGNORE_CASE)

    @Test
    fun noSuspiciousLogCalls() {
        val main = File(System.getProperty("keyvora.mainSources") ?: "src/main")
        assertTrue("sources not found at ${main.absolutePath}", main.isDirectory)
        val roots = listOf(main, File(main.parentFile, "nocore"), File(main.parentFile, "uniffi")).filter { it.isDirectory }
        val offenders = mutableListOf<String>()
        var scanned = 0
        roots.flatMap { r -> r.walkTopDown().filter { it.isFile && (it.extension == "kt" || it.extension == "java") }.toList() }
            .forEach { f ->
                scanned++
                val lines = f.readLines()
                lines.forEachIndexed { i, line ->
                    val m = logCall.find(line) ?: return@forEachIndexed
                    // The call and its arguments (up to 3 continuation lines).
                    val call = (listOf(line.substring(m.range.first)) + lines.drop(i + 1).take(3)).joinToString(" ")
                    if (suspicious.containsMatchIn(call.substringBefore(";"))) offenders += "${f.name}:${i + 1}: ${line.trim()}"
                }
            }
        assertTrue("scanned no files", scanned > 10)
        assertTrue("Log calls mentioning secrets:\n" + offenders.joinToString("\n"), offenders.isEmpty())
    }

    @Test
    fun detectorCatchesAnObviousLeak() {
        val line = """Log.d("Keyvora", "master=" + masterPassword)"""
        val m = logCall.find(line)
        assertTrue(m != null && suspicious.containsMatchIn(line.substring(m.range.first)))
    }
}
