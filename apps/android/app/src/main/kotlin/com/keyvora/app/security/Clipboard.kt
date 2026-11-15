package com.keyvora.app.security

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import android.os.SystemClock
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.util.UUID

/**
 * Pure clipboard-expiry logic (unit-tested). Each copy is tagged with a random token in the clip label so that at
 * expiry we only clear the clipboard if the clip is still ours. When the OS does not let us read the clipboard
 * (Android 10+ in background) we clear unless a change by someone else was observed since our copy.
 */
class ClipboardTimer(val clearAfterMs: Long = DEFAULT_CLEAR_AFTER_MS) {
    private var token: String? = null
    private var copiedAt = 0L
    private var changedSinceCopy = false

    val hasPending: Boolean get() = token != null

    fun onCopied(now: Long, token: String) {
        this.token = token
        copiedAt = now
        changedSinceCopy = false
    }

    /** Clipboard change notification; [currentLabel] null when unreadable. */
    fun onClipChanged(currentLabel: String?) {
        val t = token ?: return
        if (currentLabel != null && currentLabel != labelFor(t)) changedSinceCopy = true
    }

    fun dueAt(): Long? = token?.let { copiedAt + clearAfterMs }

    fun isDue(now: Long): Boolean = dueAt()?.let { now >= it } ?: false

    /** @param currentLabel label of the current clip, or null if it cannot be read. */
    fun shouldClear(currentLabel: String?): Boolean {
        val t = token ?: return false
        return if (currentLabel != null) currentLabel == labelFor(t) else !changedSinceCopy
    }

    fun onCleared() {
        token = null
        changedSinceCopy = false
    }

    companion object {
        const val DEFAULT_CLEAR_AFTER_MS = 30_000L
        private const val LABEL_PREFIX = "Keyvora:"
        fun labelFor(token: String) = LABEL_PREFIX + token
    }
}

/** Copies secrets marked as sensitive and clears them after 30 s (and on lock) if still ours (ADR-011, T18). */
class ClipboardGuard(
    context: Context,
    private val scope: CoroutineScope,
    private val elapsed: () -> Long = SystemClock::elapsedRealtime,
) {
    private val cm = context.getSystemService(ClipboardManager::class.java)
    private val timer = ClipboardTimer()
    private var job: Job? = null

    init {
        cm.addPrimaryClipChangedListener { synchronized(timer) { timer.onClipChanged(currentLabel()) } }
    }

    fun copy(text: String, sensitive: Boolean = true) {
        val token = UUID.randomUUID().toString()
        val clip = ClipData.newPlainText(ClipboardTimer.labelFor(token), text)
        if (sensitive) {
            // ClipDescription.EXTRA_IS_SENSITIVE (API 33+); harmless extra on older versions.
            clip.description.extras = PersistableBundle().apply { putBoolean(EXTRA_IS_SENSITIVE, true) }
        }
        synchronized(timer) { timer.onCopied(elapsed(), token) }
        cm.setPrimaryClip(clip)
        job?.cancel()
        job = scope.launch {
            delay(timer.clearAfterMs)
            clearIfOurs()
        }
    }

    /** Called on lock and when the timer fires. */
    fun clearIfOurs() {
        synchronized(timer) {
            if (!timer.hasPending) return
            if (timer.shouldClear(currentLabel())) clear()
            timer.onCleared()
        }
        job?.cancel()
    }

    /** Back in foreground: a frozen process may have missed the timer. */
    fun onForeground() {
        val due = synchronized(timer) { timer.isDue(elapsed()) }
        if (due) clearIfOurs()
    }

    private fun currentLabel(): String? = try {
        cm.primaryClipDescription?.label?.toString()
    } catch (_: SecurityException) {
        null
    }

    private fun clear() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) cm.clearPrimaryClip() else cm.setPrimaryClip(ClipData.newPlainText("", ""))
        } catch (_: SecurityException) {
            // Nothing else we can do.
        }
    }

    private companion object {
        const val EXTRA_IS_SENSITIVE = "android.content.extra.IS_SENSITIVE"
    }
}
