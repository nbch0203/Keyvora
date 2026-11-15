// Message handlers of the service worker (docs/CONTRACTS.md §5). Every handler validates its payload, uses the
// core for anything security-relevant (matching, crypto, generation) and returns plain data.
import type { CoreModule, CredentialMatch, Entry, EntrySummary, GeneratorOptions } from "../core/types.ts";
import { KvError, toErrorCode } from "../shared/errors.ts";
import { errReply, okReply, parseEnvelope, type MessageType, type Reply } from "../shared/messages.ts";
import type { Settings } from "../shared/settings.ts";
import { bool, entryInput, generatorOptions, int, obj, str } from "../shared/validate.ts";
import type { AutoLock } from "./autolock.ts";
import { FILL_RESULTS, type FillArgs, type FillResult } from "./inject.ts";
import type { AdoptResult, SyncStatusView } from "./sync-controller.ts";
import type { VaultService } from "./vault-service.ts";

/** New master passwords (create/change/reset): the core enforces 12 since the security review. */
export const MASTER_MIN = 12;
export const MASTER_MAX = 1024;
const MAX_CONTAINER_CHARS = 64 * 1024 * 1024;

export interface TabInfo {
  id: number;
  url?: string | undefined;
}

export interface SyncFacade {
  configured(): boolean;
  connected(): Promise<boolean>;
  status(): Promise<SyncStatusView>;
  connect(): Promise<SyncStatusView>;
  disconnect(): Promise<SyncStatusView>;
  syncNow(): Promise<SyncStatusView>;
  acknowledgeRollback(): Promise<void>;
  adoptRemoteKeys(master: string): Promise<AdoptResult>;
  markDirty(): void;
}

export interface SettingsFacade {
  get(): Promise<Settings>;
  set(patch: unknown): Promise<Settings>;
}

export interface HandlerDeps {
  core: () => Promise<CoreModule>;
  vaults: VaultService;
  settings: SettingsFacade;
  autolock: AutoLock;
  sync: SyncFacade;
  getActiveTab: () => Promise<TabInfo | null>;
  getTab: (tabId: number) => Promise<TabInfo | null>;
  inject: (tabId: number, kind: "login" | "register", args: FillArgs) => Promise<FillResult>;
  now: () => number;
}

/** Internal call context. `tabId` is only ever set by the E2E test hook, never from a message. */
export interface CallContext {
  tabId?: number;
}

export type Handler = (payload: unknown, ctx: CallContext) => Promise<unknown>;

export interface ActiveTabMatches {
  fillable: boolean;
  origin: string | null;
  host: string | null;
  matches: CredentialMatch[];
}

function backupFileName(nowMs: number): string {
  return `keyvora-copia-${new Date(nowMs).toISOString().slice(0, 10)}.json`;
}

function hostOf(origin: string): string | null {
  try {
    return new URL(origin).hostname;
  } catch {
    return null;
  }
}

export function createHandlers(d: HandlerDeps): Record<MessageType, Handler> {
  const master = (p: Record<string, unknown>, key: string) => str(p, key, { min: MASTER_MIN, max: MASTER_MAX });

  async function resolveTab(ctx: CallContext): Promise<TabInfo> {
    const tab = ctx.tabId !== undefined ? await d.getTab(ctx.tabId) : await d.getActiveTab();
    if (!tab || typeof tab.id !== "number") throw new KvError("NO_ACTIVE_TAB");
    return tab;
  }

  async function inject(tabId: number, kind: "login" | "register", args: FillArgs): Promise<FillResult> {
    let r: FillResult;
    try {
      r = await d.inject(tabId, kind, args);
    } catch {
      throw new KvError("INJECTION_FAILED");
    }
    if (!FILL_RESULTS.includes(r)) throw new KvError("INJECTION_FAILED");
    return r;
  }

  async function status() {
    const v = await d.vaults.status();
    if (v.unlocked) await d.autolock.touch();
    const s = await d.settings.get();
    return {
      ...v,
      autoLockMinutes: s.autoLockMinutes,
      sync: { configured: d.sync.configured(), connected: await d.sync.connected() },
    };
  }

  return {
    status: async () => status(),

    create: async (payload) => {
      const p = obj(payload);
      const recoveryKey = await d.vaults.create(master(p, "master"));
      return { recoveryKey };
    },

    unlock: async (payload) => {
      await d.vaults.unlock(str(obj(payload), "master", { min: 1, max: MASTER_MAX }));
      return status();
    },

    unlockRecovery: async (payload) => {
      const p = obj(payload);
      await d.vaults.unlockWithRecovery(str(p, "recoveryKey", { min: 1, max: 256 }), master(p, "newMaster"));
      return status();
    },

    lock: async () => {
      await d.vaults.lock();
      return status();
    },

    list: async (): Promise<EntrySummary[]> => d.vaults.read((v) => v.listEntries()),

    search: async (payload): Promise<EntrySummary[]> => {
      const q = str(obj(payload), "query", { max: 256, optional: true });
      return d.vaults.read((v) => v.search(q));
    },

    get: async (payload): Promise<Entry> => {
      const id = str(obj(payload), "id", { min: 1, max: 64 });
      return d.vaults.read((v) => v.getEntry(id));
    },

    createEntry: async (payload): Promise<Entry> => {
      const input = entryInput(obj(payload)["input"]);
      return d.vaults.mutate((v) => v.createEntry(input, d.now()));
    },

    updateEntry: async (payload): Promise<Entry> => {
      const p = obj(payload);
      const id = str(p, "id", { min: 1, max: 64 });
      const input = entryInput(p["input"]);
      return d.vaults.mutate((v) => v.updateEntry(id, input, d.now()));
    },

    deleteEntry: async (payload) => {
      const id = str(obj(payload), "id", { min: 1, max: 64 });
      await d.vaults.mutate((v) => v.deleteEntry(id, d.now()));
      return {};
    },

    resolveConflict: async (payload): Promise<Entry | null> => {
      const p = obj(payload);
      const id = str(p, "id", { min: 1, max: 64 });
      const choice = int(p, "choice", -1, 63);
      return d.vaults.mutate((v) => {
        v.resolveConflict(id, choice, d.now());
        // Taking a "deletion" conflict deletes the entry.
        try {
          return v.getEntry(id);
        } catch {
          return null;
        }
      });
    },

    generate: async (payload) => {
      const options: GeneratorOptions = generatorOptions(obj(payload)["options"]);
      const core = await d.core();
      return { password: core.generatePassword(options), entropyBits: core.passwordEntropyBits(options) };
    },

    matchesForActiveTab: async (_payload, ctx): Promise<ActiveTabMatches> => {
      await d.vaults.requireVault();
      const core = await d.core();
      const tab = await resolveTab(ctx).catch(() => null);
      const url = tab?.url ?? "";
      const origin = url ? (core.pageOrigin(url) ?? null) : null;
      if (!origin) return { fillable: false, origin: null, host: null, matches: [] };
      const matches = await d.vaults.read((v) => v.findMatches(url));
      return { fillable: true, origin, host: hostOf(origin), matches };
    },

    fill: async (payload, ctx) => {
      const p = obj(payload);
      const entryId = str(p, "entryId", { min: 1, max: 64 });
      const confirmed = bool(p, "confirmed");
      // Host shown in the sameSite dialog: the confirmation only counts for that host, not for wherever the tab
      // navigated meanwhile (QA-006 EXT-SEC-1).
      const confirmedHost = str(p, "confirmedHost", { max: 255, optional: true });
      await d.vaults.requireVault();
      const core = await d.core();
      const tab = await resolveTab(ctx);
      const url = tab.url ?? "";
      const expectedOrigin = url ? core.pageOrigin(url) : undefined;
      if (!expectedOrigin) throw new KvError("NOT_FILLABLE");
      const cred = await d.vaults.read((v) => {
        const m = v.findMatches(url).find((x) => x.entry.id === entryId);
        if (!m) throw new KvError("NO_MATCH");
        if (m.level === "sameSite" && (!confirmed || confirmedHost !== m.pageHost)) throw new KvError("CONFIRMATION_REQUIRED");
        if (m.level !== "exact" && m.level !== "sameSite") throw new KvError("NO_MATCH");
        const e = v.getEntry(entryId);
        return { username: e.username, password: e.password };
      });
      const result = await inject(tab.id, "login", { expectedOrigin, username: cred.username, password: cred.password });
      return { result };
    },

    generateAndFill: async (payload, ctx) => {
      const p = obj(payload);
      const title = str(p, "title", { min: 1, max: 256 });
      const username = str(p, "username", { max: 512, optional: true });
      const options = generatorOptions(p["options"]);
      await d.vaults.requireVault();
      const core = await d.core();
      const tab = await resolveTab(ctx);
      const expectedOrigin = tab.url ? core.pageOrigin(tab.url) : undefined;
      if (!expectedOrigin) throw new KvError("NOT_FILLABLE");
      const password = core.generatePassword(options);
      // Saved first: the generated password is never lost even if the page cannot be filled.
      const entry = await d.vaults.mutate((v) => v.createEntry({ title, username, password, urls: [expectedOrigin], notes: "" }, d.now()));
      const result = await inject(tab.id, "register", { expectedOrigin, username, password });
      return { entryId: entry.id, result };
    },

    changePassword: async (payload) => {
      const p = obj(payload);
      const current = str(p, "current", { min: 1, max: MASTER_MAX });
      const next = master(p, "next");
      await d.vaults.mutate((v, core) => v.changeMasterPassword(current, next, core.defaultKdfParams()));
      return {};
    },

    resetWithRecovery: async (payload) => {
      const p = obj(payload);
      const rk = str(p, "recoveryKey", { min: 1, max: 256 });
      const next = master(p, "next");
      await d.vaults.mutate((v, core) => v.resetMasterPasswordWithRecovery(rk, next, core.defaultKdfParams()));
      return {};
    },

    rotateRecovery: async (payload) => {
      const current = str(obj(payload), "current", { min: 1, max: MASTER_MAX });
      const recoveryKey = await d.vaults.mutate((v) => {
        v.rotateRecoveryKey(current);
        const rk = v.takeRecoveryKey();
        if (!rk) throw new KvError("CRYPTO");
        return rk;
      });
      return { recoveryKey };
    },

    rotateDataKey: async (payload) => {
      const current = str(obj(payload), "current", { min: 1, max: MASTER_MAX });
      await d.vaults.requireVault();
      // Merge every remote change first: after the rotation the core can no longer read containers sealed with the
      // old data key, so pending remote writes must be in the local vault before rotating (fails if offline).
      if (await d.sync.connected()) await d.sync.syncNow();
      return { recoveryKey: await d.vaults.rotateDataKey(current) };
    },

    "settings.get": async () => d.settings.get(),

    "settings.set": async (payload) => {
      const s = await d.settings.set(payload);
      await d.autolock.reschedule();
      return s;
    },

    export: async () => {
      // The persisted container is always current: it is rewritten after every mutation and merge.
      await d.vaults.requireVault();
      const container = await d.vaults.storedContainer();
      if (!container) throw new KvError("NO_VAULT");
      return { fileName: backupFileName(d.now()), container };
    },

    import: async (payload) => {
      const p = obj(payload);
      const container = str(p, "container", { min: 2, max: MAX_CONTAINER_CHARS });
      if (!(await d.vaults.hasVault())) {
        // New device restoring a backup: only accepted if it unlocks with the given master password.
        await d.vaults.adoptContainer(container, str(p, "master", { min: 1, max: MASTER_MAX }));
        return { mode: "restored" as const };
      }
      // Same vault → CRDT merge; another vault → VAULT_MISMATCH from the core (rejected, nothing changes).
      const report = await d.vaults.mutate((v) => v.mergeRemote(container));
      return { mode: "merged" as const, added: report.added, updated: report.updated, removed: report.removed, newConflicts: report.newConflicts.length };
    },

    "sync.connect": async () => d.sync.connect(),

    "sync.now": async () => {
      await d.vaults.requireVault();
      return d.sync.syncNow();
    },

    "sync.status": async (payload) => {
      if (bool(obj(payload), "acknowledgeRollback")) await d.sync.acknowledgeRollback();
      return d.sync.status();
    },

    "sync.disconnect": async () => d.sync.disconnect(),

    "sync.adoptRemoteKeys": async (payload) => {
      const master = str(obj(payload), "master", { min: 1, max: MASTER_MAX });
      await d.vaults.requireVault();
      return d.sync.adoptRemoteKeys(master);
    },
  };
}

/** Validates the envelope, runs the handler and maps errors to stable codes (no messages, no data). */
export async function dispatch(handlers: Record<MessageType, Handler>, message: unknown, ctx: CallContext = {}): Promise<Reply> {
  const env = parseEnvelope(message);
  if (!env) return errReply("BAD_REQUEST");
  try {
    const data = await handlers[env.type](env.payload, ctx);
    return okReply(data ?? null);
  } catch (e) {
    return errReply(toErrorCode(e));
  }
}
