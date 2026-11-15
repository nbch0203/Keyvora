// Client sync algorithm, docs/SYNC_PROTOCOL.md §3. The engine never decrypts anything itself: merging is done by
// the core through `SyncVault.mergeRemote`; the only thing read from a container is its plaintext `revision`
// header (used for the rollback warning).
import type { MergeReport } from "../core/types.ts";
import { KvError, toErrorCode } from "../shared/errors.ts";
import { isRetryable, RemoteError, type RemoteStore, type RevisionInfo } from "./types.ts";

export interface SyncState {
  fileId: string | null;
  lastSyncedHeadRevisionId: string | null;
  highestRemoteRevision: number;
  /** Local changes not yet uploaded. */
  dirty: boolean;
  lastSyncAt: number | null;
  lastError: string | null;
  /** Sticky until the user acknowledges it. */
  rollbackWarning: boolean;
  /**
   * The remote keys are newer (master password changed or data key rotated on another device, ADR-013): sync is
   * stopped until the user re-authenticates and the client calls `adoptRemoteKeys`.
   */
  keysChanged: boolean;
}

export function initialSyncState(): SyncState {
  return {
    fileId: null,
    lastSyncedHeadRevisionId: null,
    highestRemoteRevision: 0,
    dirty: true,
    lastSyncAt: null,
    lastError: null,
    rollbackWarning: false,
    keysChanged: false,
  };
}

export function normalizeSyncState(v: unknown): SyncState {
  const s = initialSyncState();
  if (!v || typeof v !== "object") return s;
  const o = v as Record<string, unknown>;
  const strOrNull = (x: unknown) => (typeof x === "string" ? x : null);
  s.fileId = strOrNull(o["fileId"]);
  s.lastSyncedHeadRevisionId = strOrNull(o["lastSyncedHeadRevisionId"]);
  s.highestRemoteRevision = typeof o["highestRemoteRevision"] === "number" ? o["highestRemoteRevision"] : 0;
  s.dirty = typeof o["dirty"] === "boolean" ? o["dirty"] : true;
  s.lastSyncAt = typeof o["lastSyncAt"] === "number" ? o["lastSyncAt"] : null;
  s.lastError = strOrNull(o["lastError"]);
  s.rollbackWarning = o["rollbackWarning"] === true;
  s.keysChanged = o["keysChanged"] === true;
  return s;
}

/** Access to the unlocked local vault. Both methods persist the resulting encrypted container locally. */
export interface SyncVault {
  exportContainer(): Promise<string>;
  mergeRemote(container: string): Promise<MergeReport>;
}

export interface SyncStateStore {
  load(): Promise<SyncState>;
  save(state: SyncState): Promise<void>;
}

export interface SyncEngineOptions {
  maxRounds?: number;
  /** Total attempts for retryable transport errors (NETWORK / RATE_LIMITED). */
  maxAttempts?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
  sleep?: (ms: number) => Promise<void>;
  random?: () => number;
  now?: () => number;
  /** Receives the remote container whose newer keys must be adopted (KEYRING_CHANGED). */
  onKeysChanged?: (remoteContainer: string) => Promise<void> | void;
}

export type SyncStatus = "created" | "up-to-date" | "merged" | "uploaded";

export interface MergeSummary {
  added: number;
  updated: number;
  removed: number;
  newConflicts: number;
  keyringAdopted: boolean;
  keyringConflict: boolean;
  kdfWeakened: boolean;
  recoveryKeyChanged: boolean;
}

export interface SyncResult {
  status: SyncStatus;
  rounds: number;
  attempts: number;
  rollbackWarning: boolean;
  merged: MergeSummary;
}

/** Exponential backoff 1 s, 2 s, 4 s… capped, with jitter in [d/2, d]. Honors Retry-After when larger. */
export function backoffDelay(attempt: number, baseMs: number, maxMs: number, random: () => number, retryAfterMs?: number): number {
  const d = Math.min(maxMs, baseMs * 2 ** attempt);
  const jittered = d / 2 + random() * (d / 2);
  return Math.min(maxMs, Math.max(jittered, retryAfterMs ?? 0));
}

/** Plaintext `revision` of a container header, or null if it cannot be read. */
export function containerRevision(container: string): number | null {
  try {
    const r = (JSON.parse(container) as Record<string, unknown>)["revision"];
    return typeof r === "number" && Number.isSafeInteger(r) && r >= 0 ? r : null;
  } catch {
    return null;
  }
}

/**
 * Revisions strictly between `fromId` (the head we merged before uploading) and `toId` (our upload).
 * If `fromId` is no longer listed (purged), every listed revision before `toId` modified at or after
 * `fromModifiedTime` is taken (merging extra revisions is harmless: the merge is idempotent).
 */
export function intermediateRevisions(revs: RevisionInfo[], fromId: string, toId: string, fromModifiedTime: string): RevisionInfo[] {
  const toIdx = revs.findIndex((r) => r.id === toId);
  const end = toIdx === -1 ? revs.length : toIdx;
  const fromIdx = revs.findIndex((r) => r.id === fromId);
  if (fromIdx !== -1) return revs.slice(fromIdx + 1, end).filter((r) => r.id !== toId);
  return revs.slice(0, end).filter((r) => r.id !== fromId && r.id !== toId && r.modifiedTime >= fromModifiedTime);
}

function emptySummary(): MergeSummary {
  return { added: 0, updated: 0, removed: 0, newConflicts: 0, keyringAdopted: false, keyringConflict: false, kdfWeakened: false, recoveryKeyChanged: false };
}

/** Counters of a single merge report (e.g. the result of adoptRemoteKeys). */
export function summarize(r: MergeReport): MergeSummary {
  const s = emptySummary();
  accumulate(s, r);
  return s;
}

function accumulate(s: MergeSummary, r: MergeReport): void {
  s.added += r.added;
  s.updated += r.updated;
  s.removed += r.removed;
  s.newConflicts += r.newConflicts.length;
  s.keyringAdopted ||= r.keyringAdopted;
  s.keyringConflict ||= r.keyringConflict;
  s.kdfWeakened ||= r.kdfWeakened === true;
  s.recoveryKeyChanged ||= r.recoveryKeyChanged === true;
}

export class SyncEngine {
  readonly #remote: RemoteStore;
  readonly #vault: SyncVault;
  readonly #store: SyncStateStore;
  readonly #maxRounds: number;
  readonly #maxAttempts: number;
  readonly #baseDelayMs: number;
  readonly #maxDelayMs: number;
  readonly #sleep: (ms: number) => Promise<void>;
  readonly #random: () => number;
  readonly #now: () => number;
  readonly #onKeysChanged: ((remoteContainer: string) => Promise<void> | void) | undefined;
  #state: SyncState | null = null;
  /** Incremented on every local change; lets a sync know whether changes happened while it was running. */
  #changeGen = 0;
  #running: Promise<SyncResult> | null = null;

  constructor(remote: RemoteStore, vault: SyncVault, store: SyncStateStore, opts: SyncEngineOptions = {}) {
    this.#remote = remote;
    this.#vault = vault;
    this.#store = store;
    this.#maxRounds = opts.maxRounds ?? 5;
    this.#maxAttempts = opts.maxAttempts ?? 5;
    this.#baseDelayMs = opts.baseDelayMs ?? 1000;
    this.#maxDelayMs = opts.maxDelayMs ?? 60_000;
    this.#sleep = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.#random = opts.random ?? Math.random;
    this.#now = opts.now ?? Date.now;
    this.#onKeysChanged = opts.onKeysChanged;
  }

  get running(): boolean {
    return this.#running !== null;
  }

  async getState(): Promise<SyncState> {
    if (!this.#state) this.#state = normalizeSyncState(await this.#store.load());
    return this.#state;
  }

  /** Records a local change (call after every persisted mutation). */
  async markDirty(): Promise<void> {
    this.#changeGen++;
    const s = await this.getState();
    if (!s.dirty) {
      s.dirty = true;
      await this.#store.save(s);
    }
  }

  async acknowledgeRollback(): Promise<void> {
    const s = await this.getState();
    s.rollbackWarning = false;
    await this.#store.save(s);
  }

  /** The user re-authenticated and the remote keys were adopted: sync may resume (uploading if needed). */
  async keysAdopted(needsUpload: boolean): Promise<void> {
    const s = await this.getState();
    s.keysChanged = false;
    if (s.lastError === "KEYRING_CHANGED") s.lastError = null;
    if (needsUpload) {
      this.#changeGen++;
      s.dirty = true;
    }
    await this.#store.save(s);
  }

  /** Forgets remote bookkeeping (disconnect). Local data is untouched and will be merged/uploaded on reconnect. */
  async reset(): Promise<void> {
    this.#state = initialSyncState();
    await this.#store.save(this.#state);
  }

  /** Runs a sync; concurrent callers share the in-flight run. */
  sync(): Promise<SyncResult> {
    if (!this.#running) {
      this.#running = this.#runWithRetries().finally(() => {
        this.#running = null;
      });
    }
    return this.#running;
  }

  async #runWithRetries(): Promise<SyncResult> {
    const s = await this.getState();
    for (let attempt = 0; ; attempt++) {
      try {
        const r = await this.#runOnce(s);
        s.lastError = null;
        s.keysChanged = false;
        s.lastSyncAt = this.#now();
        await this.#store.save(s);
        return { ...r, attempts: attempt + 1 };
      } catch (e) {
        const code = toErrorCode(e);
        if (isRetryable(code) && attempt + 1 < this.#maxAttempts) {
          const retryAfter = e instanceof RemoteError ? e.retryAfterMs : undefined;
          await this.#sleep(backoffDelay(attempt, this.#baseDelayMs, this.#maxDelayMs, this.#random, retryAfter));
          continue;
        }
        if (code !== "LOCKED") s.lastError = code;
        await this.#store.save(s);
        throw e;
      }
    }
  }

  async #runOnce(s: SyncState): Promise<Omit<SyncResult, "attempts">> {
    const merged = emptySummary();
    // KEYRING_CHANGED: nothing was modified by the core; stop, remember the container and let the user decide.
    const merge = async (content: string): Promise<MergeReport> => {
      try {
        return await this.#vault.mergeRemote(content);
      } catch (e) {
        if (toErrorCode(e) === "KEYRING_CHANGED") {
          s.keysChanged = true;
          await this.#store.save(s);
          await this.#onKeysChanged?.(content);
        }
        throw e;
      }
    };
    const done = (status: SyncStatus, rounds: number) => ({ status, rounds, rollbackWarning: s.rollbackWarning, merged });

    for (let round = 1; round <= this.#maxRounds; round++) {
      const meta = await this.#remote.getMetadata();

      if (!meta) {
        // First upload (or the remote file was removed): local data is complete, upload it as is.
        const gen = this.#changeGen;
        const content = await this.#vault.exportContainer();
        const created = await this.#remote.create(content);
        s.fileId = created.fileId;
        s.lastSyncedHeadRevisionId = created.headRevisionId;
        s.highestRemoteRevision = Math.max(s.highestRemoteRevision, containerRevision(content) ?? 0);
        s.dirty = this.#changeGen !== gen;
        await this.#store.save(s);
        return done("created", round);
      }

      let rev: string;
      if (meta.headRevisionId === s.lastSyncedHeadRevisionId) {
        if (!s.dirty) return done("up-to-date", round);
        // The head is the revision we last merged or wrote ourselves: its content is already contained in the local
        // vault, so re-downloading and re-merging it would be a no-op. Skipping it also lets a device that has just
        // rotated its data key publish the rotation (the core cannot decrypt containers sealed with the old key).
        rev = meta.headRevisionId;
      } else {
        const gen = this.#changeGen;
        const downloaded = await this.#remote.download(meta.fileId);
        rev = downloaded.headRevisionId;
        const remoteRevision = containerRevision(downloaded.content);
        if (remoteRevision !== null && remoteRevision < s.highestRemoteRevision) s.rollbackWarning = true;

        // Fails closed (INTEGRITY_ERROR / VAULT_MISMATCH / KEYRING_CHANGED) without touching the local vault.
        const report = await merge(downloaded.content);
        accumulate(merged, report);
        s.fileId = meta.fileId;
        s.highestRemoteRevision = Math.max(s.highestRemoteRevision, report.remoteRevision);

        if (!report.needsUpload) {
          s.lastSyncedHeadRevisionId = rev;
          s.dirty = this.#changeGen !== gen;
          await this.#store.save(s);
          if (!s.dirty) return done(report.adoptedRemote && hasChanges(report) ? "merged" : "up-to-date", round);
          continue;
        }
      }

      s.dirty = true;
      await this.#store.save(s);

      // headRevisionId pre-check: someone wrote while we were merging → start a new round.
      const meta2 = await this.#remote.getMetadata();
      if (!meta2 || meta2.headRevisionId !== rev) continue;

      const genUpload = this.#changeGen;
      const local = await this.#vault.exportContainer();
      const uploaded = await this.#remote.update(meta.fileId, local);
      s.highestRemoteRevision = Math.max(s.highestRemoteRevision, containerRevision(local) ?? 0);

      // Post-upload check: merge any revision written between our read and our write.
      const revs = await this.#remote.listRevisions(meta.fileId);
      const intermediate = intermediateRevisions(revs, rev, uploaded.headRevisionId, meta.modifiedTime);
      for (const r of intermediate) {
        const older = await this.#remote.downloadRevision(meta.fileId, r.id);
        accumulate(merged, await merge(older));
      }
      s.lastSyncedHeadRevisionId = uploaded.headRevisionId;
      s.dirty = intermediate.length > 0 || this.#changeGen !== genUpload;
      await this.#store.save(s);
      if (!s.dirty) return done("uploaded", round);
    }
    throw new KvError("CONFLICT_RETRY_EXHAUSTED");
  }
}

function hasChanges(r: MergeReport): boolean {
  return r.added + r.updated + r.removed > 0 || r.newConflicts.length > 0 || r.keyringAdopted;
}
