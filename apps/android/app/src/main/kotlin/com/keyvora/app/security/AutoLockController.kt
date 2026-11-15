package com.keyvora.app.security

import android.os.SystemClock
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import com.keyvora.app.vault.AppSettings
import com.keyvora.app.vault.VaultManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/** Wires [AutoLockTimer] to the process lifecycle (ProcessLifecycleOwner) and to user interaction. */
class AutoLockController(
    private val vault: VaultManager,
    private val settings: AppSettings,
    private val clipboard: ClipboardGuard,
    private val mainScope: CoroutineScope,
    private val elapsed: () -> Long = SystemClock::elapsedRealtime,
) : DefaultLifecycleObserver {
    private val timer = AutoLockTimer(settings.autoLock.millis)
    private var backgroundJob: Job? = null
    private var inactivityJob: Job? = null
    private var foreground = false

    fun install() {
        ProcessLifecycleOwner.get().lifecycle.addObserver(this)
        vault.addUnlockListener {
            mainScope.launch {
                timer.onUnlocked(elapsed())
                scheduleInactivity()
            }
        }
        vault.addLockListener {
            mainScope.launch {
                backgroundJob?.cancel()
                inactivityJob?.cancel()
            }
        }
    }

    override fun onStart(owner: LifecycleOwner) {
        foreground = true
        backgroundJob?.cancel()
        clipboard.onForeground()
        if (vault.isUnlocked && timer.onForeground(elapsed())) vault.lock()
        scheduleInactivity()
    }

    override fun onStop(owner: LifecycleOwner) {
        foreground = false
        inactivityJob?.cancel()
        if (!vault.isUnlocked) return
        val delayMs = timer.onBackground(elapsed())
        if (delayMs <= 0) {
            vault.lock()
        } else {
            backgroundJob?.cancel()
            backgroundJob = mainScope.launch {
                delay(delayMs)
                vault.lock()
            }
        }
    }

    fun onUserInteraction() = timer.onInteraction(elapsed())

    /**
     * Deadline check against `elapsedRealtime` for entry points that use the vault without bringing the app to the
     * foreground (autofill service, its activities). The background lock job uses `delay` (uptime: it stops in deep
     * sleep and in a frozen process), so on its own it can fire hours late (QA-006 AND-SEC-2). Main thread only.
     * @return true if the vault is locked (already, or now because the deadline had passed).
     */
    fun lockIfExpired(): Boolean {
        if (!vault.isUnlocked) return true
        val now = elapsed()
        if (if (foreground) timer.isInactive(now) else timer.backgroundExpired(now)) vault.lock()
        return !vault.isUnlocked
    }

    /** Call right before launching a system picker / consent screen that puts the app in background. */
    fun expectExternalActivity() = timer.expectExternalActivity(elapsed())

    fun onDelayChanged() {
        timer.setDelay(settings.autoLock.millis)
        scheduleInactivity()
    }

    private fun scheduleInactivity() {
        inactivityJob?.cancel()
        if (!foreground || !vault.isUnlocked) return
        inactivityJob = mainScope.launch {
            while (isActive) {
                val now = elapsed()
                if (timer.isInactive(now)) {
                    vault.lock()
                    break
                }
                delay(timer.msUntilInactive(now).coerceAtLeast(1_000))
            }
        }
    }
}
