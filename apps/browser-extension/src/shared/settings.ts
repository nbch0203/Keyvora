import { KvError } from "./errors.ts";

export interface Settings {
  /** Minutes of inactivity before the vault locks (1–60). */
  autoLockMinutes: number;
}

export const DEFAULT_SETTINGS: Readonly<Settings> = Object.freeze({ autoLockMinutes: 5 });
export const AUTOLOCK_MIN = 1;
export const AUTOLOCK_MAX = 60;

export function isValidAutoLock(v: unknown): v is number {
  return typeof v === "number" && Number.isInteger(v) && v >= AUTOLOCK_MIN && v <= AUTOLOCK_MAX;
}

/** Validates a settings patch from the popup. Unknown keys or invalid values → BAD_REQUEST. */
export function validateSettingsPatch(input: unknown): Partial<Settings> {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new KvError("BAD_REQUEST");
  const o = input as Record<string, unknown>;
  const out: Partial<Settings> = {};
  for (const k of Object.keys(o)) {
    if (k !== "autoLockMinutes" || !isValidAutoLock(o[k])) throw new KvError("BAD_REQUEST");
    out.autoLockMinutes = o[k];
  }
  return out;
}

/** Normalizes whatever is stored (possibly old or corrupted) into valid settings. */
export function normalizeSettings(stored: unknown): Settings {
  const o = stored && typeof stored === "object" ? (stored as Record<string, unknown>) : {};
  const m = o["autoLockMinutes"];
  return { autoLockMinutes: isValidAutoLock(m) ? m : DEFAULT_SETTINGS.autoLockMinutes };
}
