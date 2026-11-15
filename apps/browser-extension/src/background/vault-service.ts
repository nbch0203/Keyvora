// Owns the unlocked vault handle in the service worker.
// - Encrypted container: storage.local (`vault.container`), rewritten after every mutation.
// - DEK of the unlocked session: storage.session only (memory, TRUSTED_CONTEXTS), so a restarted service worker can
//   reopen with `openWithDataKey`. Locking wipes the WASM handle and clears storage.session.
import type { CoreModule, CoreVault, MergeReport } from "../core/types.ts";
import { KvError } from "../shared/errors.ts";
import type { KeyValueArea } from "../shared/storage.ts";
import type { AutoLock } from "./autolock.ts";

export const KEYS = {
  container: "vault.container",
  deviceId: "deviceId",
  dek: "session.dek",
  pendingRemote: "session.pendingRemote",
} as const;

export interface VaultServiceDeps {
  core: () => Promise<CoreModule>;
  local: KeyValueArea;
  session: KeyValueArea;
  autolock: AutoLock;
  now: () => number;
  randomUUID: () => string;
  onUnlocked?: () => void;
  onLocked?: () => void;
  /** Called after every persisted local change (marks the sync state dirty). */
  onMutation?: () => void;
}

export interface VaultStatus {
  hasVault: boolean;
  unlocked: boolean;
  /** A remote container was downloaded (Drive bootstrap) and waits for the master password. */
  pendingRemote: boolean;
}

export function bytesToBase64(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]!);
  return btoa(s);
}

export function base64ToBytes(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function dispose(v: CoreVault | null): void {
  if (!v) return;
  try {
    v.lock();
  } catch {
    /* already locked */
  }
  try {
    v.free();
  } catch {
    /* already freed */
  }
}

export class VaultService {
  readonly #d: VaultServiceDeps;
  #vault: CoreVault | null = null;
  #queue: Promise<unknown> = Promise.resolve();
  #restoring: Promise<CoreVault | null> | null = null;

  constructor(deps: VaultServiceDeps) {
    this.#d = deps;
  }

  /** Serializes operations that read-modify-write the vault or its storage. Never call re-entrantly. */
  exclusive<T>(fn: () => Promise<T> | T): Promise<T> {
    const run = this.#queue.then(fn, fn);
    this.#queue = run.catch(() => undefined);
    return run;
  }

  async deviceId(): Promise<string> {
    const v = (await this.#d.local.get([KEYS.deviceId]))[KEYS.deviceId];
    if (typeof v === "string" && /^[A-Za-z0-9_-]{1,64}$/.test(v)) return v;
    const id = this.#d.randomUUID();
    await this.#d.local.set({ [KEYS.deviceId]: id });
    return id;
  }

  async storedContainer(): Promise<string | null> {
    const v = (await this.#d.local.get([KEYS.container]))[KEYS.container];
    return typeof v === "string" && v.length > 0 ? v : null;
  }

  async hasVault(): Promise<boolean> {
    return (await this.storedContainer()) !== null;
  }

  async saveContainer(container: string): Promise<void> {
    await this.#d.local.set({ [KEYS.container]: container });
  }

  async pendingRemote(): Promise<string | null> {
    const v = (await this.#d.session.get([KEYS.pendingRemote]))[KEYS.pendingRemote];
    return typeof v === "string" && v.length > 0 ? v : null;
  }

  /** Keeps a container downloaded from Drive until the user unlocks it (no local vault yet). */
  async setPendingRemote(container: string): Promise<void> {
    await this.#d.session.set({ [KEYS.pendingRemote]: container });
  }

  async status(): Promise<VaultStatus> {
    const hasVault = await this.hasVault();
    const unlocked = hasVault && (await this.#restore()) !== null;
    return { hasVault, unlocked, pendingRemote: !hasVault && (await this.pendingRemote()) !== null };
  }

  /** Current handle, reopening it from the session DEK after a service-worker restart. */
  async #restore(): Promise<CoreVault | null> {
    if (this.#vault) {
      // The lock alarm may not have fired yet (e.g. resume from sleep): a message after the deadline must lock, not
      // extend the session (QA-006 EXT-SEC-2).
      if (!(await this.#d.autolock.expired())) return this.#vault;
      await this.#lockNow();
      return null;
    }
    if (!this.#restoring) {
      this.#restoring = this.#doRestore().finally(() => {
        this.#restoring = null;
      });
    }
    return this.#restoring;
  }

  async #doRestore(): Promise<CoreVault | null> {
    const dekB64 = (await this.#d.session.get([KEYS.dek]))[KEYS.dek];
    if (typeof dekB64 !== "string") return null;
    if (await this.#d.autolock.expired()) {
      await this.#lockNow();
      return null;
    }
    const container = await this.storedContainer();
    if (!container) {
      await this.#lockNow();
      return null;
    }
    const core = await this.#d.core();
    const deviceId = await this.deviceId();
    const dek = base64ToBytes(dekB64);
    try {
      this.#vault = core.openWithDataKey(container, dek, deviceId);
      return this.#vault;
    } catch {
      await this.#lockNow();
      return null;
    } finally {
      dek.fill(0);
    }
  }

  /**
   * The unlocked vault, or LOCKED. `userActivity` (default) postpones the auto-lock; background work such as
   * sync passes false so that it never keeps a session alive.
   */
  async requireVault(userActivity = true): Promise<CoreVault> {
    const v = await this.#restore();
    if (!v) throw new KvError("LOCKED");
    if (userActivity) await this.#d.autolock.touch();
    return v;
  }

  /** For the sync engine: exports (and persists) the current container without counting as activity. */
  syncExport(): Promise<string> {
    return this.exclusive(async () => {
      const v = await this.requireVault(false);
      const c = v.exportContainer();
      await this.saveContainer(c);
      return c;
    });
  }

  /** For the sync engine: merges a remote container and persists the result. */
  syncMerge(container: string): Promise<MergeReport> {
    return this.exclusive(async () => {
      const v = await this.requireVault(false);
      const report = v.mergeRemote(container);
      await this.saveContainer(v.exportContainer());
      return report;
    });
  }

  async read<T>(fn: (v: CoreVault) => T | Promise<T>): Promise<T> {
    return fn(await this.requireVault());
  }

  /**
   * Runs a change and persists the encrypted container before returning. `rekey` refreshes the session DEK
   * (needed after operations that replace the data key, e.g. rotateDataKey).
   */
  mutate<T>(fn: (v: CoreVault, core: CoreModule) => T, opts: { rekey?: boolean } = {}): Promise<T> {
    return this.exclusive(async () => {
      const v = await this.requireVault();
      const core = await this.#d.core();
      const out = fn(v, core);
      await this.saveContainer(v.exportContainer());
      if (opts.rekey) await this.#storeSessionKey(v);
      this.#d.onMutation?.();
      return out;
    });
  }

  /** New data key + new recovery key (shown once). Old secrets keep opening only old copies. */
  rotateDataKey(currentMaster: string): Promise<string> {
    return this.mutate((v) => {
      v.rotateDataKey(currentMaster);
      const rk = v.takeRecoveryKey();
      if (!rk) throw new KvError("CRYPTO");
      return rk;
    }, { rekey: true });
  }

  /**
   * After KEYRING_CHANGED: re-authenticates with the master password valid for the remote container, adopts its
   * keys (merging local data), persists and refreshes the session DEK (it changes if the remote rotated it).
   */
  adoptRemoteKeys(remoteContainer: string, master: string): Promise<MergeReport> {
    return this.exclusive(async () => {
      const v = await this.requireVault();
      const report = v.adoptRemoteKeys(remoteContainer, master);
      await this.saveContainer(v.exportContainer());
      await this.#storeSessionKey(v);
      return report;
    });
  }

  async #storeSessionKey(v: CoreVault): Promise<void> {
    const dek = v.exportDataKey();
    try {
      await this.#d.session.set({ [KEYS.dek]: bytesToBase64(dek) });
    } finally {
      dek.fill(0);
    }
  }

  async #startSession(v: CoreVault): Promise<void> {
    // Activity first: #restore() treats an in-memory handle without recorded activity as expired.
    await this.#d.autolock.touch(true);
    dispose(this.#vault !== v ? this.#vault : null);
    this.#vault = v;
    await this.#storeSessionKey(v);
    this.#d.onUnlocked?.();
  }

  /** Creates a new vault; returns the recovery key, which is shown once and never stored. */
  create(master: string): Promise<string> {
    return this.exclusive(async () => {
      if (await this.hasVault()) throw new KvError("VAULT_EXISTS");
      const core = await this.#d.core();
      const deviceId = await this.deviceId();
      const v = core.create(master, core.defaultKdfParams(), deviceId, this.#d.now());
      try {
        const rk = v.takeRecoveryKey();
        if (!rk) throw new KvError("CRYPTO");
        await this.saveContainer(v.exportContainer());
        await this.#d.session.remove([KEYS.pendingRemote]);
        await this.#startSession(v);
        this.#d.onMutation?.();
        return rk;
      } catch (e) {
        if (this.#vault !== v) dispose(v);
        throw e;
      }
    });
  }

  /** Unlocks the local vault, or the pending remote one (Drive bootstrap) which then becomes the local vault. */
  unlock(master: string): Promise<void> {
    return this.exclusive(async () => {
      const local = await this.storedContainer();
      const container = local ?? (await this.pendingRemote());
      if (!container) throw new KvError("NO_VAULT");
      const core = await this.#d.core();
      const v = core.unlockWithPassword(container, master, await this.deviceId());
      if (!local) {
        await this.saveContainer(v.exportContainer());
        await this.#d.session.remove([KEYS.pendingRemote]);
      }
      await this.#startSession(v);
    });
  }

  /** Unlocks with the recovery key and immediately sets a new master password (mandatory). */
  unlockWithRecovery(recoveryKey: string, newMaster: string): Promise<void> {
    return this.exclusive(async () => {
      const container = (await this.storedContainer()) ?? (await this.pendingRemote());
      if (!container) throw new KvError("NO_VAULT");
      const core = await this.#d.core();
      const v = core.unlockWithRecoveryKey(container, recoveryKey, await this.deviceId());
      try {
        v.resetMasterPasswordWithRecovery(recoveryKey, newMaster, core.defaultKdfParams());
        await this.saveContainer(v.exportContainer());
        await this.#d.session.remove([KEYS.pendingRemote]);
      } catch (e) {
        dispose(v);
        throw e;
      }
      await this.#startSession(v);
      this.#d.onMutation?.();
    });
  }

  /** Restores a vault from an encrypted backup when this device has none (validated by unlocking it). */
  adoptContainer(container: string, master: string): Promise<void> {
    return this.exclusive(async () => {
      if (await this.hasVault()) throw new KvError("VAULT_EXISTS");
      const core = await this.#d.core();
      const v = core.unlockWithPassword(container, master, await this.deviceId());
      try {
        await this.saveContainer(v.exportContainer());
      } catch (e) {
        dispose(v);
        throw e;
      }
      await this.#startSession(v);
      this.#d.onMutation?.();
    });
  }

  /** Locks after any in-flight mutation finished. */
  lock(): Promise<void> {
    return this.exclusive(() => this.#lockNow());
  }

  async #lockNow(): Promise<void> {
    const v = this.#vault;
    this.#vault = null;
    dispose(v);
    await this.#d.session.clear();
    await this.#d.autolock.cancel();
    this.#d.onLocked?.();
  }
}
