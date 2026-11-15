// Inactivity auto-lock with chrome.alarms. The last activity time lives in storage.session so that it survives
// service-worker restarts; the alarm is only a wake-up, the decision is always recomputed from the stored time.
import type { KeyValueArea } from "../shared/storage.ts";

export const AUTOLOCK_ALARM = "keyvora-autolock";
export const LAST_ACTIVITY_KEY = "session.lastActivity";
/** Activity is persisted at most this often (every message would otherwise write to storage). */
export const TOUCH_THROTTLE_MS = 5_000;

export function lockDeadline(lastActivityMs: number, minutes: number): number {
  return lastActivityMs + minutes * 60_000;
}

export function isExpired(nowMs: number, lastActivityMs: number | null | undefined, minutes: number): boolean {
  if (typeof lastActivityMs !== "number" || !Number.isFinite(lastActivityMs)) return true;
  // A clock that went backwards must not extend the session indefinitely.
  if (lastActivityMs > nowMs + 60_000) return true;
  return nowMs >= lockDeadline(lastActivityMs, minutes);
}

export interface AlarmsLike {
  create(name: string, info: { when: number }): unknown;
  clear(name: string): unknown;
}

export interface AutoLockOptions {
  alarms: AlarmsLike;
  session: KeyValueArea;
  now: () => number;
  minutes: () => Promise<number>;
}

export class AutoLock {
  readonly #o: AutoLockOptions;
  #lastPersisted = 0;

  constructor(opts: AutoLockOptions) {
    this.#o = opts;
  }

  async lastActivity(): Promise<number | null> {
    const v = (await this.#o.session.get([LAST_ACTIVITY_KEY]))[LAST_ACTIVITY_KEY];
    return typeof v === "number" ? v : null;
  }

  /** Records user activity and moves the lock alarm. */
  async touch(force = false): Promise<void> {
    const now = this.#o.now();
    if (!force && now - this.#lastPersisted < TOUCH_THROTTLE_MS) return;
    this.#lastPersisted = now;
    await this.#o.session.set({ [LAST_ACTIVITY_KEY]: now });
    await this.#schedule(now);
  }

  /** True when the session must be locked (expired or no recorded activity). */
  async expired(): Promise<boolean> {
    return isExpired(this.#o.now(), await this.lastActivity(), await this.#o.minutes());
  }

  /** Re-arms the alarm from the stored activity time (after a settings change or an early wake-up). */
  async reschedule(): Promise<void> {
    const last = await this.lastActivity();
    if (last !== null) await this.#schedule(last);
  }

  async cancel(): Promise<void> {
    this.#lastPersisted = 0;
    await this.#o.alarms.clear(AUTOLOCK_ALARM);
  }

  async #schedule(from: number): Promise<void> {
    const when = Math.max(lockDeadline(from, await this.#o.minutes()), this.#o.now() + 1000);
    await this.#o.alarms.create(AUTOLOCK_ALARM, { when });
  }
}
