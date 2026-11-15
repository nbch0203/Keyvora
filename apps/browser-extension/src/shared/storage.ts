// Thin async key/value abstraction over chrome.storage areas, with an in-memory implementation for tests.

export interface KeyValueArea {
  get(keys: string[]): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(keys: string[]): Promise<void>;
  clear(): Promise<void>;
}

/** In-memory area (tests, and as a model of chrome.storage semantics: values are deep-copied). */
export class MemoryArea implements KeyValueArea {
  readonly data = new Map<string, unknown>();

  async get(keys: string[]): Promise<Record<string, unknown>> {
    const out: Record<string, unknown> = {};
    for (const k of keys) if (this.data.has(k)) out[k] = structuredClone(this.data.get(k));
    return out;
  }
  async set(items: Record<string, unknown>): Promise<void> {
    for (const [k, v] of Object.entries(items)) this.data.set(k, structuredClone(v));
  }
  async remove(keys: string[]): Promise<void> {
    for (const k of keys) this.data.delete(k);
  }
  async clear(): Promise<void> {
    this.data.clear();
  }
}

/** Minimal promise-based view of chrome.storage.StorageArea (MV3 returns promises in Chromium and Firefox). */
export interface ChromeStorageAreaLike {
  get(keys: string[]): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(keys: string[]): Promise<void>;
  clear(): Promise<void>;
}

export function chromeArea(area: ChromeStorageAreaLike): KeyValueArea {
  return {
    get: (keys) => area.get(keys),
    set: (items) => area.set(items),
    remove: (keys) => area.remove(keys),
    clear: () => area.clear(),
  };
}
