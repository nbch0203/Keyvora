import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { AUTOLOCK_ALARM, AutoLock, isExpired, LAST_ACTIVITY_KEY, lockDeadline, TOUCH_THROTTLE_MS } from "../../src/background/autolock.ts";
import { SettingsStore } from "../../src/background/settings-store.ts";
import { DEFAULT_SETTINGS, normalizeSettings, validateSettingsPatch } from "../../src/shared/settings.ts";
import { MemoryArea } from "../../src/shared/storage.ts";
import { FakeAlarms, FakeClock } from "./helpers/fakes.ts";

describe("settings validation", () => {
  test("default auto-lock is 5 minutes", () => {
    assert.equal(DEFAULT_SETTINGS.autoLockMinutes, 5);
    assert.deepEqual(normalizeSettings(undefined), { autoLockMinutes: 5 });
  });
  test("accepts 1–60 integer minutes", () => {
    assert.deepEqual(validateSettingsPatch({ autoLockMinutes: 1 }), { autoLockMinutes: 1 });
    assert.deepEqual(validateSettingsPatch({ autoLockMinutes: 60 }), { autoLockMinutes: 60 });
    assert.deepEqual(validateSettingsPatch({}), {});
  });
  test("rejects out of range, non-integers, wrong types and unknown keys", () => {
    for (const p of [{ autoLockMinutes: 0 }, { autoLockMinutes: 61 }, { autoLockMinutes: 2.5 }, { autoLockMinutes: "5" },
      { autoLockMinutes: Number.NaN }, { other: 1 }, null, [], "x"]) {
      assert.throws(() => validateSettingsPatch(p), /BAD_REQUEST/, JSON.stringify(p));
    }
  });
  test("normalizes corrupted stored values to defaults", () => {
    assert.deepEqual(normalizeSettings({ autoLockMinutes: 999 }), { autoLockMinutes: 5 });
    assert.deepEqual(normalizeSettings({ autoLockMinutes: 15, junk: true }), { autoLockMinutes: 15 });
  });
  test("SettingsStore persists validated patches", async () => {
    const local = new MemoryArea();
    const s = new SettingsStore(local);
    assert.deepEqual(await s.get(), { autoLockMinutes: 5 });
    assert.deepEqual(await s.set({ autoLockMinutes: 12 }), { autoLockMinutes: 12 });
    assert.deepEqual(await new SettingsStore(local).get(), { autoLockMinutes: 12 });
    await assert.rejects(s.set({ autoLockMinutes: 0 }), /BAD_REQUEST/);
  });
});

describe("auto-lock logic", () => {
  test("deadline and expiry", () => {
    assert.equal(lockDeadline(1000, 5), 1000 + 300_000);
    assert.equal(isExpired(1000 + 299_999, 1000, 5), false);
    assert.equal(isExpired(1000 + 300_000, 1000, 5), true);
    assert.equal(isExpired(5000, null, 5), true, "no recorded activity → locked");
    assert.equal(isExpired(5000, 5000 + 3_600_000, 5), true, "activity in the future (clock change) → locked");
  });

  function setup(minutes = 5) {
    const clock = new FakeClock();
    const alarms = new FakeAlarms();
    const session = new MemoryArea();
    let m = minutes;
    const al = new AutoLock({ alarms, session, now: clock.now, minutes: async () => m });
    return { clock, alarms, session, al, setMinutes: (v: number) => (m = v) };
  }

  test("touch records activity in session storage and arms the alarm", async () => {
    const { clock, alarms, session, al } = setup(5);
    await al.touch(true);
    assert.equal(session.data.get(LAST_ACTIVITY_KEY), clock.t);
    assert.equal(alarms.alarms.get(AUTOLOCK_ALARM), clock.t + 5 * 60_000);
    assert.equal(await al.expired(), false);
    clock.advance(5 * 60_000);
    assert.equal(await al.expired(), true);
  });

  test("activity postpones the lock; writes are throttled", async () => {
    const { clock, alarms, al } = setup(5);
    await al.touch(true);
    const first = alarms.alarms.get(AUTOLOCK_ALARM)!;
    clock.advance(TOUCH_THROTTLE_MS - 1);
    await al.touch();
    assert.equal(alarms.alarms.get(AUTOLOCK_ALARM), first, "throttled");
    clock.advance(4 * 60_000);
    await al.touch();
    assert.ok(alarms.alarms.get(AUTOLOCK_ALARM)! > first);
    clock.advance(4 * 60_000);
    assert.equal(await al.expired(), false);
  });

  test("changing the minutes reschedules from the last activity", async () => {
    const { clock, alarms, al, setMinutes } = setup(30);
    await al.touch(true);
    const start = clock.t;
    setMinutes(1);
    await al.reschedule();
    assert.equal(alarms.alarms.get(AUTOLOCK_ALARM), start + 60_000);
    clock.advance(61_000);
    assert.equal(await al.expired(), true);
  });

  test("cancel clears the alarm; an empty session counts as expired", async () => {
    const { session, alarms, al } = setup();
    await al.touch(true);
    await al.cancel();
    assert.equal(alarms.alarms.has(AUTOLOCK_ALARM), false);
    await session.clear();
    assert.equal(await al.expired(), true);
  });
});
