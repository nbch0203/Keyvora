package com.keyvora.app.security

/**
 * Pure auto-lock timing logic (no Android types; unit-tested). Times are monotonic milliseconds
 * (`SystemClock.elapsedRealtime()` in the app).
 *
 * - Background: with delay 0 the vault locks as soon as the app leaves the foreground; otherwise after `delay`.
 *   The check is repeated on return to foreground, because a frozen/cached process may never run its timer.
 * - Inactivity in foreground: locks after `max(delay, MIN_INACTIVITY_MS)` without user interaction
 *   ("inmediato" therefore means 1 minute of inactivity while visible).
 * - An expected external activity (SAF picker, Google consent) gets a grace period instead of the immediate lock.
 */
class AutoLockTimer(private var delayMs: Long) {
    private var backgroundSince: Long? = null
    private var lastInteraction: Long = 0
    private var graceUntil: Long? = null

    fun setDelay(ms: Long) { delayMs = ms }

    fun onUnlocked(now: Long) {
        lastInteraction = now
        backgroundSince = null
    }

    fun onInteraction(now: Long) { lastInteraction = now }

    /** The next background transition is expected (system picker / consent screen). */
    fun expectExternalActivity(now: Long) { graceUntil = now + EXTERNAL_GRACE_MS }

    /** @return delay in ms after which to lock (0 = lock now). */
    fun onBackground(now: Long): Long {
        backgroundSince = now
        val grace = graceUntil?.takeIf { it > now }
        return if (grace != null) maxOf(delayMs, grace - now) else delayMs
    }

    /** @return true if the vault must be locked because the background period exceeded the allowed delay. */
    fun onForeground(now: Long): Boolean {
        val since = backgroundSince ?: return false
        val expired = now - since >= allowedSince(since)
        backgroundSince = null
        graceUntil = null
        lastInteraction = now
        return expired
    }

    /**
     * Read-only check (no state change) for code that uses the vault while the app stays in background (autofill):
     * has the background period already exceeded the allowed delay? `now` must be `elapsedRealtime` (counts deep sleep).
     */
    fun backgroundExpired(now: Long): Boolean {
        val since = backgroundSince ?: return false
        return now - since >= allowedSince(since)
    }

    private fun allowedSince(since: Long): Long {
        val grace = graceUntil
        return if (grace != null && grace > since) maxOf(delayMs, grace - since) else delayMs
    }

    fun inactivityTimeoutMs(): Long = maxOf(delayMs, MIN_INACTIVITY_MS)

    fun isInactive(now: Long): Boolean = now - lastInteraction >= inactivityTimeoutMs()

    /** Milliseconds until the inactivity deadline (≥ 0). */
    fun msUntilInactive(now: Long): Long = maxOf(0, lastInteraction + inactivityTimeoutMs() - now)

    companion object {
        const val MIN_INACTIVITY_MS = 60_000L
        const val EXTERNAL_GRACE_MS = 3 * 60_000L
    }
}
