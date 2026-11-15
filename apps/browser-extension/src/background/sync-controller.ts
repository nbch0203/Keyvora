// Glue between the service worker, the vault and the SyncEngine: connection state, triggers (unlock, debounced
// after mutations, manual, retry alarm) and the status shown in the popup.
import { KvError, toErrorCode } from "../shared/errors.ts";
import type { KeyValueArea } from "../shared/storage.ts";
import { summarize, SyncEngine, type MergeSummary, type SyncEngineOptions, type SyncState } from "../sync/engine.ts";
import type { RemoteStore } from "../sync/types.ts";
import type { VaultService } from "./vault-service.ts";

export const SYNC_STATE_KEY = "sync.state";
export const SYNC_CONNECTED_KEY = "sync.connected";
export const SYNC_RETRY_ALARM = "keyvora-sync-retry";
export const SYNC_DEBOUNCE_MS = 3_000;
/** storage.session: remote container whose newer keys await the user's master password (ADR-013). */
export const PENDING_KEYS_KEY = "sync.pendingRemoteKeys";

export interface SyncAuth {
  connect(): Promise<void>;
  disconnect(): Promise<void>;
}

export interface SyncStatusView {
  configured: boolean;
  connected: boolean;
  syncing: boolean;
  dirty: boolean;
  lastSyncAt: number | null;
  lastError: string | null;
  rollbackWarning: boolean;
  /** Remote keys changed on another device: ask for the master password, then `sync.adoptRemoteKeys`. */
  keysChanged: boolean;
  lastMerge: MergeSummary | null;
}

export interface AdoptResult {
  merged: MergeSummary;
  kdfWeakened: boolean;
  recoveryKeyChanged: boolean;
  sync: SyncStatusView;
}

export interface SyncControllerDeps {
  /** null when the build has no OAuth client id ("no configurado"). */
  auth: SyncAuth | null;
  remote: RemoteStore | null;
  vaults: VaultService;
  local: KeyValueArea;
  session: KeyValueArea;
  alarms?: { create(name: string, info: { delayInMinutes: number }): unknown; clear(name: string): unknown };
  engineOptions?: SyncEngineOptions;
  setTimer?: (fn: () => void, ms: number) => unknown;
  clearTimer?: (h: unknown) => void;
}

export class SyncController {
  readonly #d: SyncControllerDeps;
  readonly #engine: SyncEngine | null;
  #timer: unknown = null;
  #lastMerge: MergeSummary | null = null;

  constructor(deps: SyncControllerDeps) {
    this.#d = deps;
    const local = deps.local;
    this.#engine = deps.remote
      ? new SyncEngine(
          deps.remote,
          { exportContainer: () => deps.vaults.syncExport(), mergeRemote: (c) => deps.vaults.syncMerge(c) },
          {
            load: async () => (await local.get([SYNC_STATE_KEY]))[SYNC_STATE_KEY] as SyncState,
            save: (s) => local.set({ [SYNC_STATE_KEY]: s }),
          },
          { ...deps.engineOptions, onKeysChanged: (c) => deps.session.set({ [PENDING_KEYS_KEY]: c }) },
        )
      : null;
  }

  configured(): boolean {
    return this.#d.auth !== null && this.#engine !== null;
  }

  async connected(): Promise<boolean> {
    return this.configured() && (await this.#d.local.get([SYNC_CONNECTED_KEY]))[SYNC_CONNECTED_KEY] === true;
  }

  async status(): Promise<SyncStatusView> {
    const s = this.#engine ? await this.#engine.getState() : null;
    return {
      configured: this.configured(),
      connected: await this.connected(),
      syncing: this.#engine?.running ?? false,
      dirty: s?.dirty ?? false,
      lastSyncAt: s?.lastSyncAt ?? null,
      lastError: s?.lastError ?? null,
      rollbackWarning: s?.rollbackWarning ?? false,
      keysChanged: s?.keysChanged ?? false,
      lastMerge: this.#lastMerge,
    };
  }

  #require(): { auth: SyncAuth; engine: SyncEngine; remote: RemoteStore } {
    if (!this.#d.auth || !this.#engine || !this.#d.remote) throw new KvError("SYNC_NOT_CONFIGURED");
    return { auth: this.#d.auth, engine: this.#engine, remote: this.#d.remote };
  }

  /**
   * Interactive OAuth, then: with a local vault → sync now; without one → download the remote vault and keep it
   * pending until the user unlocks it with the master password (second device).
   */
  async connect(): Promise<SyncStatusView> {
    const { auth, engine, remote } = this.#require();
    await auth.connect();
    await this.#d.local.set({ [SYNC_CONNECTED_KEY]: true });
    if (await this.#d.vaults.hasVault()) {
      await engine.markDirty();
      if ((await this.#d.vaults.status()).unlocked) await this.syncNow().catch(() => undefined);
    } else {
      const meta = await remote.getMetadata();
      if (!meta) throw new KvError("REMOTE_EMPTY");
      const { content } = await remote.download(meta.fileId);
      await this.#d.vaults.setPendingRemote(content);
    }
    return this.status();
  }

  async disconnect(): Promise<SyncStatusView> {
    const { auth, engine } = this.#require();
    this.#cancelTimer();
    await auth.disconnect();
    await this.#d.local.set({ [SYNC_CONNECTED_KEY]: false });
    await engine.reset();
    this.#lastMerge = null;
    await this.#d.alarms?.clear(SYNC_RETRY_ALARM);
    return this.status();
  }

  /**
   * The user typed the master password that is valid for the remote container (changed or rotated elsewhere).
   * Wrong password → INVALID_CREDENTIALS and nothing changes. Then sync resumes (uploading local changes if needed).
   */
  async adoptRemoteKeys(master: string): Promise<AdoptResult> {
    const { engine, remote } = this.#require();
    let container = (await this.#d.session.get([PENDING_KEYS_KEY]))[PENDING_KEYS_KEY];
    if (typeof container !== "string") {
      // Session was cleared (lock/restart) since the sync that detected it: read the current remote head.
      const meta = await remote.getMetadata();
      if (!meta) throw new KvError("REMOTE_EMPTY");
      container = (await remote.download(meta.fileId)).content;
    }
    const report = await this.#d.vaults.adoptRemoteKeys(container as string, master);
    await this.#d.session.remove([PENDING_KEYS_KEY]);
    const merged = summarize(report);
    await engine.keysAdopted(report.needsUpload);
    this.#lastMerge = merged;
    if (await this.connected()) {
      await this.syncNow().catch(() => undefined);
      if (this.#lastMerge) {
        this.#lastMerge.kdfWeakened ||= merged.kdfWeakened;
        this.#lastMerge.recoveryKeyChanged ||= merged.recoveryKeyChanged;
      }
    }
    return {
      merged,
      kdfWeakened: report.kdfWeakened === true,
      recoveryKeyChanged: report.recoveryKeyChanged === true,
      sync: await this.status(),
    };
  }

  async acknowledgeRollback(): Promise<void> {
    await this.#engine?.acknowledgeRollback();
  }

  /** Manual / triggered sync. Throws the sync error code. */
  async syncNow(): Promise<SyncStatusView> {
    const { engine } = this.#require();
    if (!(await this.connected())) throw new KvError("SYNC_NOT_CONNECTED");
    this.#cancelTimer();
    try {
      const r = await engine.sync();
      this.#lastMerge = r.merged;
      await this.#d.alarms?.clear(SYNC_RETRY_ALARM);
    } catch (e) {
      const code = toErrorCode(e);
      if (code === "NETWORK" || code === "RATE_LIMITED" || code === "CONFLICT_RETRY_EXHAUSTED") {
        await this.#d.alarms?.create(SYNC_RETRY_ALARM, { delayInMinutes: 5 });
      }
      throw e;
    }
    return this.status();
  }

  /** Local change persisted: mark dirty and sync a few seconds later (debounced). */
  markDirty(): void {
    if (!this.#engine) return;
    void this.#engine.markDirty().then(() => this.schedule());
  }

  onUnlocked(): void {
    this.schedule(0);
  }

  async onRetryAlarm(): Promise<void> {
    if ((await this.connected()) && (await this.#d.vaults.status()).unlocked) await this.syncNow().catch(() => undefined);
  }

  schedule(delayMs = SYNC_DEBOUNCE_MS): void {
    if (!this.#engine) return;
    this.#cancelTimer();
    const set = this.#d.setTimer ?? ((fn, ms) => setTimeout(fn, ms));
    this.#timer = set(() => {
      this.#timer = null;
      void this.connected().then((c) => (c ? this.syncNow().catch(() => undefined) : undefined));
    }, delayMs);
  }

  #cancelTimer(): void {
    if (this.#timer !== null) {
      (this.#d.clearTimer ?? ((h) => clearTimeout(h as ReturnType<typeof setTimeout>)))(this.#timer);
      this.#timer = null;
    }
  }
}
