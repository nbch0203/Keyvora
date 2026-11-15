package com.keyvora.app.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ClipboardTimerTest {
    private val t = ClipboardTimer()
    private val ours = ClipboardTimer.labelFor("tok")

    @Test
    fun clearsAfterThirtySecondsWhenStillOurs() {
        t.onCopied(1_000, "tok")
        assertEquals(31_000L, t.dueAt())
        assertFalse(t.isDue(30_999))
        assertTrue(t.isDue(31_000))
        assertTrue(t.shouldClear(ours))
    }

    @Test
    fun doesNotClearSomeoneElsesClip() {
        t.onCopied(0, "tok")
        assertFalse(t.shouldClear("Other app label"))
        assertFalse(t.shouldClear(ClipboardTimer.labelFor("older-token")))
    }

    @Test
    fun unreadableClipboardIsClearedUnlessAChangeWasObserved() {
        t.onCopied(0, "tok")
        assertTrue(t.shouldClear(null))
        t.onClipChanged(ours) // our own change notification
        assertTrue(t.shouldClear(null))
        t.onClipChanged("copied by user elsewhere")
        assertFalse(t.shouldClear(null))
    }

    @Test
    fun newCopyResetsAndClearForgetsToken() {
        t.onCopied(0, "a")
        t.onClipChanged("x")
        t.onCopied(5_000, "tok")
        assertTrue(t.shouldClear(null))
        assertEquals(35_000L, t.dueAt())
        t.onCleared()
        assertNull(t.dueAt())
        assertFalse(t.shouldClear(ours))
        assertFalse(t.isDue(Long.MAX_VALUE))
    }
}

class AutoLockTimerTest {
    @Test
    fun immediateLocksOnBackground() {
        val t = AutoLockTimer(0)
        t.onUnlocked(0)
        assertEquals(0L, t.onBackground(10))
    }

    @Test
    fun delayedLockOnBackgroundAndCheckOnForeground() {
        val t = AutoLockTimer(5 * 60_000L)
        t.onUnlocked(0)
        assertEquals(300_000L, t.onBackground(1_000))
        assertFalse(t.onForeground(1_000 + 299_999))
        t.onBackground(400_000)
        assertTrue("timer may not have run in a frozen process", t.onForeground(400_000 + 300_000))
    }

    @Test
    fun backgroundExpiredIsAReadOnlyWallClockCheck() {
        // QA-006 AND-SEC-2: the coroutine timer may not have run (deep sleep / frozen process); autofill asks directly.
        val t = AutoLockTimer(15 * 60_000L)
        t.onUnlocked(0)
        assertFalse("still in foreground", t.backgroundExpired(10_000_000))
        t.onBackground(1_000)
        assertFalse(t.backgroundExpired(1_000 + 899_999))
        assertTrue(t.backgroundExpired(1_000 + 900_000))
        assertTrue("read-only: asking again gives the same answer", t.backgroundExpired(5 * 3_600_000L))
        assertTrue("and onForeground still locks", t.onForeground(5 * 3_600_000L))
        assertFalse("back in foreground", t.backgroundExpired(6 * 3_600_000L))
    }

    @Test
    fun backgroundExpiredHonoursTheExternalActivityGrace() {
        val t = AutoLockTimer(0)
        t.onUnlocked(0)
        t.expectExternalActivity(1_000)
        t.onBackground(2_000)
        assertFalse(t.backgroundExpired(30_000))
        assertTrue(t.backgroundExpired(1_000 + AutoLockTimer.EXTERNAL_GRACE_MS))
    }

    @Test
    fun foregroundWithoutBackgroundNeverLocks() {
        val t = AutoLockTimer(60_000)
        t.onUnlocked(0)
        assertFalse(t.onForeground(10_000_000))
    }

    @Test
    fun inactivityUsesDelayWithOneMinuteMinimum() {
        val t = AutoLockTimer(0)
        t.onUnlocked(0)
        assertEquals(60_000L, t.inactivityTimeoutMs())
        assertFalse(t.isInactive(59_999))
        assertTrue(t.isInactive(60_000))
        t.onInteraction(50_000)
        assertFalse(t.isInactive(100_000))
        assertEquals(10_000L, t.msUntilInactive(100_000))

        val t15 = AutoLockTimer(15 * 60_000L)
        t15.onUnlocked(0)
        assertEquals(900_000L, t15.inactivityTimeoutMs())
        t15.setDelay(60_000)
        assertTrue(t15.isInactive(60_000))
    }

    @Test
    fun externalActivityGetsGracePeriod() {
        val t = AutoLockTimer(0)
        t.onUnlocked(0)
        t.expectExternalActivity(1_000)
        val d = t.onBackground(2_000)
        assertEquals(AutoLockTimer.EXTERNAL_GRACE_MS - 1_000, d)
        assertFalse(t.onForeground(30_000)) // back from the picker in time
        // grace is single-use
        assertEquals(0L, t.onBackground(40_000))
        assertTrue(t.onForeground(40_001))
    }

    @Test
    fun expiredGraceDoesNotApply() {
        val t = AutoLockTimer(60_000)
        t.onUnlocked(0)
        t.expectExternalActivity(0)
        assertEquals(60_000L, t.onBackground(AutoLockTimer.EXTERNAL_GRACE_MS + 1))
    }
}
