import { normalizeSettings, validateSettingsPatch, type Settings } from "../shared/settings.ts";
import type { KeyValueArea } from "../shared/storage.ts";

export const SETTINGS_KEY = "settings";

export class SettingsStore {
  readonly #local: KeyValueArea;
  #cache: Settings | null = null;

  constructor(local: KeyValueArea) {
    this.#local = local;
  }

  async get(): Promise<Settings> {
    if (!this.#cache) this.#cache = normalizeSettings((await this.#local.get([SETTINGS_KEY]))[SETTINGS_KEY]);
    return { ...this.#cache };
  }

  /** Validates and stores a patch; returns the resulting settings. */
  async set(patch: unknown): Promise<Settings> {
    const p = validateSettingsPatch(patch);
    const next = { ...(await this.get()), ...p };
    await this.#local.set({ [SETTINGS_KEY]: next });
    this.#cache = next;
    return { ...next };
  }
}
