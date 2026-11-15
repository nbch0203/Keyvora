// Service-worker logic (VaultService + handlers + sync) against the real WASM core, with fake chrome APIs.
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { AutoLock } from "../../src/background/autolock.ts";
import { createHandlers, dispatch, type SyncFacade, type TabInfo } from "../../src/background/handlers.ts";
import type { FillArgs, FillResult } from "../../src/background/inject.ts";
import { SettingsStore } from "../../src/background/settings-store.ts";
import { SyncController, type AdoptResult, type SyncStatusView } from "../../src/background/sync-controller.ts";
import { base64ToBytes, KEYS, VaultService } from "../../src/background/vault-service.ts";
import type { CoreModule, Entry, EntrySummary } from "../../src/core/types.ts";
import type { Reply } from "../../src/shared/messages.ts";
import { MemoryArea } from "../../src/shared/storage.ts";
import { SyncEngine, type SyncState } from "../../src/sync/engine.ts";
import { InMemoryRemoteStore } from "../../src/sync/in-memory.ts";
import { loadRealCore, SKIP_NO_CORE, withFastKdf } from "./helpers/core.ts";
import { FakeAlarms, FakeClock } from "./helpers/fakes.ts";

const real = await loadRealCore();
const skip = real ? false : SKIP_NO_CORE;
const MASTER = "correcto caballo batería grapa";

const noSync: SyncFacade = {
  configured: () => false,
  connected: async () => false,
  status: async () => ({ configured: false, connected: false, syncing: false, dirty: false, lastSyncAt: null, lastError: null, rollbackWarning: false, keysChanged: false, lastMerge: null }),
  connect: async () => Promise.reject(new Error("SYNC_NOT_CONFIGURED")),
  disconnect: async () => Promise.reject(new Error("SYNC_NOT_CONFIGURED")),
  syncNow: async () => Promise.reject(new Error("SYNC_NOT_CONFIGURED")),
  acknowledgeRollback: async () => undefined,
  adoptRemoteKeys: async () => Promise.reject(new Error("SYNC_NOT_CONFIGURED")),
  markDirty: () => undefined,
};

function worker(opts: { local?: MemoryArea; session?: MemoryArea; clock?: FakeClock; deviceId?: string; remote?: InMemoryRemoteStore } = {}) {
  const core: CoreModule = withFastKdf(real!);
  const local = opts.local ?? new MemoryArea();
  const session = opts.session ?? new MemoryArea();
  const clock = opts.clock ?? new FakeClock();
  const alarms = new FakeAlarms();
  const settings = new SettingsStore(local);
  const autolock = new AutoLock({ alarms, session, now: clock.now, minutes: async () => (await settings.get()).autoLockMinutes });
  let mutations = 0;
  let controller: SyncController | null = null;
  const vaults = new VaultService({
    core: async () => core,
    local,
    session,
    autolock,
    now: clock.now,
    randomUUID: () => opts.deviceId ?? "device-a",
    onMutation: () => {
      mutations++;
      controller?.markDirty();
    },
  });
  if (opts.remote) {
    // Real SyncController over the in-memory Drive; OAuth stubbed, timers disabled (tests call sync.now explicitly).
    controller = new SyncController({
      auth: { connect: async () => undefined, disconnect: async () => undefined },
      remote: opts.remote,
      vaults,
      local,
      session,
      engineOptions: { sleep: async () => undefined },
      setTimer: () => null,
      clearTimer: () => undefined,
    });
  }
  const tabs = new Map<number, TabInfo>();
  let active: number | null = null;
  const injections: Array<{ tabId: number; kind: string; args: FillArgs }> = [];
  let injectResult: FillResult = "filled";
  const handlers = createHandlers({
    core: async () => core,
    vaults,
    settings,
    autolock,
    sync: controller ?? noSync,
    getActiveTab: async () => (active === null ? null : (tabs.get(active) ?? null)),
    getTab: async (id) => tabs.get(id) ?? null,
    inject: async (tabId, kind, args) => {
      injections.push({ tabId, kind, args });
      return injectResult;
    },
    now: clock.now,
  });
  const call = <T = unknown>(type: string, payload?: unknown, tabId?: number) =>
    dispatch(handlers, { v: 1, type, payload }, tabId === undefined ? {} : { tabId }) as Promise<Reply<T>>;
  const ok = async <T = unknown>(type: string, payload?: unknown, tabId?: number): Promise<T> => {
    const r = await call<T>(type, payload, tabId);
    if (!r.ok) assert.fail(`${type} failed with ${r.error}`);
    return r.data;
  };
  return {
    core, local, session, clock, alarms, vaults, call, ok, injections,
    get mutations() {
      return mutations;
    },
    openTab(id: number, url: string, makeActive = true) {
      tabs.set(id, { id, url });
      if (makeActive) active = id;
    },
    setInjectResult(r: FillResult) {
      injectResult = r;
    },
  };
}

async function created(w = worker()) {
  const { recoveryKey } = await w.ok<{ recoveryKey: string }>("create", { master: MASTER });
  return { w, recoveryKey };
}

describe("vault session in the service worker (real core)", { skip }, () => {
  test("create → recovery key once, container in local, DEK only in session", async () => {
    const { w, recoveryKey } = await created();
    assert.match(recoveryKey, /^[A-Z2-7]{4}(-[A-Z2-7]{4}){13}$/);
    const st = await w.ok<{ hasVault: boolean; unlocked: boolean }>("status");
    assert.equal(st.hasVault, true);
    assert.equal(st.unlocked, true);
    const container = w.local.data.get(KEYS.container) as string;
    assert.equal(JSON.parse(container).format, "keyvora.vault");
    assert.ok(!container.includes(MASTER) && !container.includes(recoveryKey));
    assert.equal(typeof w.session.data.get(KEYS.dek), "string");
    assert.equal(w.local.data.has(KEYS.dek), false, "DEK never in storage.local");
    assert.equal((await w.call("create", { master: MASTER })).ok, false, "second vault rejected");
    assert.deepEqual(await w.call("create", { master: "short" }), { ok: false, error: "BAD_REQUEST" });
  });

  test("entries CRUD persists the encrypted container after every mutation", async () => {
    const { w } = await created();
    const before = w.local.data.get(KEYS.container);
    const e = await w.ok<Entry>("createEntry", { input: { title: "GitHub", username: "alice", password: "pw-1", urls: ["https://github.com"], notes: "" } });
    assert.notEqual(w.local.data.get(KEYS.container), before);
    assert.ok(!(w.local.data.get(KEYS.container) as string).includes("pw-1"));
    await w.ok("updateEntry", { id: e.id, input: { title: "GitHub", username: "alice", password: "pw-2", urls: ["https://github.com"], notes: "n" } });
    const got = await w.ok<Entry>("get", { id: e.id });
    assert.equal(got.password, "pw-2");
    assert.equal(got.passwordHistory[0]!.password, "pw-1");
    assert.equal((await w.ok<EntrySummary[]>("search", { query: "git" })).length, 1);
    await w.ok("deleteEntry", { id: e.id });
    assert.deepEqual(await w.ok("list"), []);
    assert.equal(w.mutations >= 4, true);
  });

  test("service-worker restart reopens the session with openWithDataKey", async () => {
    const { w } = await created();
    await w.ok("createEntry", { input: { title: "A", username: "", password: "x", urls: [], notes: "" } });
    const w2 = worker({ local: w.local, session: w.session, clock: w.clock });
    const st = await w2.ok<{ unlocked: boolean }>("status");
    assert.equal(st.unlocked, true);
    assert.equal((await w2.ok<EntrySummary[]>("list")).length, 1);
  });

  test("auto-lock: after the inactivity period a restarted worker is locked and the session is wiped", async () => {
    const { w } = await created();
    await w.ok("settings.set", { autoLockMinutes: 1 });
    w.clock.advance(61_000);
    const w2 = worker({ local: w.local, session: w.session, clock: w.clock });
    assert.deepEqual(await w2.call("list"), { ok: false, error: "LOCKED" });
    assert.equal(w.session.data.size, 0);
  });

  test("lock wipes session storage; operations then fail with LOCKED; unlock checks the password", async () => {
    const { w } = await created();
    await w.ok("lock");
    assert.equal(w.session.data.size, 0);
    assert.deepEqual(await w.call("list"), { ok: false, error: "LOCKED" });
    assert.deepEqual(await w.call("unlock", { master: "wrong password" }), { ok: false, error: "INVALID_CREDENTIALS" });
    await w.ok("unlock", { master: MASTER });
    assert.deepEqual(await w.ok("list"), []);
  });

  test("recovery: unlock with the recovery key forces a new master password", async () => {
    const { w, recoveryKey } = await created();
    await w.ok("lock");
    assert.deepEqual(await w.call("unlockRecovery", { recoveryKey: "AAAA-BBBB", newMaster: "nueva maestra larga" }), { ok: false, error: "INVALID_RECOVERY_KEY" });
    await w.ok("unlockRecovery", { recoveryKey: recoveryKey.toLowerCase().replaceAll("-", " "), newMaster: "nueva maestra larga" });
    await w.ok("lock");
    assert.equal((await w.call("unlock", { master: MASTER })).ok, false, "old master no longer works");
    await w.ok("unlock", { master: "nueva maestra larga" });
  });

  test("change master password and rotate recovery key", async () => {
    const { w, recoveryKey } = await created();
    assert.deepEqual(await w.call("changePassword", { current: "nope nope", next: "otra maestra 123" }), { ok: false, error: "INVALID_CREDENTIALS" });
    await w.ok("changePassword", { current: MASTER, next: "otra maestra 123" });
    const { recoveryKey: rk2 } = await w.ok<{ recoveryKey: string }>("rotateRecovery", { current: "otra maestra 123" });
    assert.notEqual(rk2, recoveryKey);
    await w.ok("lock");
    assert.equal((await w.call("unlockRecovery", { recoveryKey, newMaster: "xxxxxxxxxxxx" })).ok, false, "old recovery key revoked");
    await w.ok("unlock", { master: "otra maestra 123" });
    await w.ok("resetWithRecovery", { recoveryKey: rk2, next: "tercera maestra" });
    await w.ok("lock");
    await w.ok("unlock", { master: "tercera maestra" });
  });

  test("export / import: same vault merges, another vault is rejected, fresh install restores", async () => {
    const { w } = await created();
    await w.ok("createEntry", { input: { title: "A", username: "", password: "x", urls: [], notes: "" } });
    const { container, fileName } = await w.ok<{ container: string; fileName: string }>("export");
    assert.match(fileName, /^keyvora-copia-\d{4}-\d{2}-\d{2}\.json$/);
    await w.ok("createEntry", { input: { title: "B", username: "", password: "y", urls: [], notes: "" } });
    const merged = await w.ok<{ mode: string }>("import", { container });
    assert.equal(merged.mode, "merged");
    assert.equal((await w.ok<EntrySummary[]>("list")).length, 2, "merge never loses newer local data");

    const other = (await created(worker({ deviceId: "device-z" }))).w;
    const { container: foreign } = await other.ok<{ container: string }>("export");
    assert.deepEqual(await w.call("import", { container: foreign }), { ok: false, error: "VAULT_MISMATCH" });

    const fresh = worker({ deviceId: "device-b" });
    assert.equal((await fresh.call("import", { container, master: "wrong password" })).ok, false);
    assert.equal(fresh.local.data.has(KEYS.container), false, "nothing stored on failure");
    assert.equal((await fresh.ok<{ mode: string }>("import", { container, master: MASTER })).mode, "restored");
    assert.equal((await fresh.ok<EntrySummary[]>("list")).length, 1);
  });

  test("generate validates options and reports entropy", async () => {
    const { w } = await created();
    const g = await w.ok<{ password: string; entropyBits: number }>("generate", { options: { length: 32, symbols: false } });
    assert.equal(g.password.length, 32);
    assert.match(g.password, /^[A-Za-z0-9]+$/);
    assert.ok(g.entropyBits > 150);
    assert.deepEqual(await w.call("generate", { options: { length: 7 } }), { ok: false, error: "BAD_REQUEST" });
  });
});

describe("autofill decisions (real core, fake tabs)", { skip }, () => {
  async function withEntries() {
    const { w } = await created();
    const ex = await w.ok<Entry>("createEntry", { input: { title: "Example", username: "alice", password: "pw-ex", urls: ["https://example.com"], notes: "" } });
    const acc = await w.ok<Entry>("createEntry", { input: { title: "Accounts", username: "bob", password: "pw-acc", urls: ["https://accounts.example.com"], notes: "" } });
    const other = await w.ok<Entry>("createEntry", { input: { title: "Other", username: "eve", password: "pw-other", urls: ["https://other.example.org"], notes: "" } });
    return { w, ex, acc, other };
  }

  test("exact match fills the top frame with only that credential and the core-computed origin", async () => {
    const { w, ex, acc } = await withEntries();
    w.openTab(7, "https://example.com/login?next=/");
    const m = await w.ok<{ fillable: boolean; origin: string; matches: Array<{ entry: { id: string }; level: string }> }>("matchesForActiveTab");
    assert.equal(m.fillable, true);
    assert.equal(m.origin, "https://example.com");
    // Best first; accounts.example.com shares the registrable domain → sameSite; other.example.org never offered.
    assert.deepEqual(m.matches.map((x) => [x.entry.id, x.level]), [[ex.id, "exact"], [acc.id, "sameSite"]]);
    assert.deepEqual(await w.ok("fill", { entryId: ex.id }), { result: "filled" });
    assert.deepEqual(w.injections, [{ tabId: 7, kind: "login", args: { expectedOrigin: "https://example.com", username: "alice", password: "pw-ex" } }]);
  });

  test("entry of another site is never filled", async () => {
    const { w, other } = await withEntries();
    w.openTab(7, "https://example.com/login");
    assert.deepEqual(await w.call("fill", { entryId: other.id }), { ok: false, error: "NO_MATCH" });
    assert.deepEqual(await w.call("fill", { entryId: "00000000-0000-4000-8000-000000000000" }), { ok: false, error: "NO_MATCH" });
    w.openTab(8, "https://example.com.evil.example/login");
    const { ex } = { ex: (await w.ok<EntrySummary[]>("list")).find((e) => e.title === "Example")! };
    assert.deepEqual(await w.call("fill", { entryId: ex.id }), { ok: false, error: "NO_MATCH" });
    assert.equal(w.injections.length, 0);
  });

  test("sameSite requires explicit confirmation", async () => {
    const { w, acc } = await withEntries();
    w.openTab(9, "https://login.example.com/");
    const m = await w.ok<{ matches: Array<{ entry: { id: string }; level: string; pageHost: string }> }>("matchesForActiveTab");
    const s = m.matches.find((x) => x.entry.id === acc.id)!;
    assert.equal(s.level, "sameSite");
    assert.equal(s.pageHost, "login.example.com");
    assert.deepEqual(await w.call("fill", { entryId: acc.id }), { ok: false, error: "CONFIRMATION_REQUIRED" });
    assert.equal(w.injections.length, 0);
    assert.deepEqual(await w.ok("fill", { entryId: acc.id, confirmed: true }), { result: "filled" });
    assert.equal(w.injections[0]!.args.expectedOrigin, "https://login.example.com");
  });

  test("non-HTTPS pages and missing tab URLs are not fillable", async () => {
    const { w, ex } = await withEntries();
    w.openTab(10, "http://example.com/login");
    assert.deepEqual(await w.call("fill", { entryId: ex.id }), { ok: false, error: "NOT_FILLABLE" });
    assert.equal((await w.ok<{ fillable: boolean }>("matchesForActiveTab")).fillable, false);
    w.openTab(11, "chrome://settings");
    assert.deepEqual(await w.call("fill", { entryId: ex.id }), { ok: false, error: "NOT_FILLABLE" });
    assert.equal(w.injections.length, 0);
  });

  test("page results (ambiguous / no-form / origin-mismatch) are passed through; garbage → INJECTION_FAILED", async () => {
    const { w, ex } = await withEntries();
    w.openTab(7, "https://example.com/");
    w.setInjectResult("ambiguous");
    assert.deepEqual(await w.ok("fill", { entryId: ex.id }), { result: "ambiguous" });
    w.setInjectResult("<script>" as FillResult);
    assert.deepEqual(await w.call("fill", { entryId: ex.id }), { ok: false, error: "INJECTION_FAILED" });
  });

  test("generateAndFill saves the entry first, for the page origin, then fills the registration form", async () => {
    const { w } = await withEntries();
    w.openTab(12, "https://signup.example.net/register");
    const r = await w.ok<{ entryId: string; result: string }>("generateAndFill", { title: "Nuevo", username: "zoe", options: { length: 24 } });
    assert.equal(r.result, "filled");
    const e = await w.ok<Entry>("get", { id: r.entryId });
    assert.deepEqual(e.urls, ["https://signup.example.net"]);
    assert.equal(e.password.length, 24);
    assert.deepEqual(w.injections.at(-1), { tabId: 12, kind: "register", args: { expectedOrigin: "https://signup.example.net", username: "zoe", password: e.password } });
  });

  test("after lock, fill fails with LOCKED and nothing is injected", async () => {
    const { w, ex } = await withEntries();
    w.openTab(7, "https://example.com/");
    await w.ok("lock");
    assert.deepEqual(await w.call("fill", { entryId: ex.id }), { ok: false, error: "LOCKED" });
    assert.equal(w.injections.length, 0);
  });
});

describe("sync between two devices through InMemoryRemoteStore (real core)", { skip }, () => {
  function engineFor(w: ReturnType<typeof worker>, remote: InMemoryRemoteStore) {
    let st: SyncState | undefined;
    return new SyncEngine(
      remote,
      { exportContainer: () => w.vaults.syncExport(), mergeRemote: (c) => w.vaults.syncMerge(c) },
      { load: async () => st as SyncState, save: async (s) => void (st = structuredClone(s)) },
      { sleep: async () => undefined },
    );
  }

  test("devices converge; concurrent edits of one entry become a conflict, nothing is lost; Drive only sees ciphertext", async () => {
    const remote = new InMemoryRemoteStore();
    const a = (await created(worker({ deviceId: "device-a" }))).w;
    const e = await a.ok<Entry>("createEntry", {
      input: { title: "Shared", username: "shared-user@example.com", password: "initial-secret-v1", urls: [], notes: "" },
    });
    const ea = engineFor(a, remote);
    assert.equal((await ea.sync()).status, "created");
    // Needles must be long: short strings (e.g. "v1") appear by chance inside Base64 ciphertext.
    for (const needle of ["Shared", "shared-user@example.com", "initial-secret-v1"]) {
      assert.ok(!remote.headContent!.includes(needle), `Drive content leaks ${needle}`);
    }

    // Device B joins from Drive (same vault, its own device id).
    const b = worker({ deviceId: "device-b" });
    await b.ok("import", { container: remote.headContent!, master: MASTER });
    const eb = engineFor(b, remote);
    await eb.sync();

    // Concurrent edits: different entries on each side + the same entry on both.
    await a.ok("createEntry", { input: { title: "Only A", username: "", password: "a", urls: [], notes: "" } });
    await a.ok("updateEntry", { id: e.id, input: { title: "Shared", username: "u", password: "from-A", urls: [], notes: "" } });
    await b.ok("createEntry", { input: { title: "Only B", username: "", password: "b", urls: [], notes: "" } });
    await b.ok("updateEntry", { id: e.id, input: { title: "Shared", username: "u", password: "from-B", urls: [], notes: "" } });
    await ea.markDirty();
    await eb.markDirty();
    await ea.sync();
    await eb.sync();
    await ea.sync();

    const titles = async (w: typeof a) => (await w.ok<EntrySummary[]>("list")).map((x) => x.title).sort();
    assert.deepEqual(await titles(a), ["Only A", "Only B", "Shared"]);
    assert.deepEqual(await titles(b), ["Only A", "Only B", "Shared"]);
    const sa = await a.ok<Entry>("get", { id: e.id });
    const passwords = [sa.password, ...sa.conflicts.map((c) => c.password)].sort();
    assert.deepEqual(passwords, ["from-A", "from-B"], "the losing edit is kept as a conflict");
    // Resolve on A and propagate to B.
    await a.ok("resolveConflict", { id: e.id, choice: -1 });
    await ea.markDirty();
    await ea.sync();
    await eb.sync();
    const sb = await b.ok<Entry>("get", { id: e.id });
    assert.equal(sb.conflicts.length, 0);
    assert.equal(sb.password, sa.password);
  });
});

describe("key policy after the security review (ADR-013, real core)", { skip }, () => {
  const NEW_MASTER = "cambiada en el dispositivo A";

  async function pair() {
    const remote = new InMemoryRemoteStore();
    const a = (await created(worker({ deviceId: "device-a", remote }))).w;
    await a.ok("createEntry", { input: { title: "Desde A", username: "a", password: "secret-from-device-a", urls: [], notes: "" } });
    await a.ok("sync.connect");
    const b = worker({ deviceId: "device-b", remote });
    await b.ok("import", { container: remote.headContent!, master: MASTER });
    await b.ok("sync.connect");
    return { remote, a, b };
  }

  test("new master passwords need at least 12 characters", async () => {
    const w = worker();
    assert.deepEqual(await w.call("create", { master: "once-chars!" }), { ok: false, error: "BAD_REQUEST" });
    await w.ok("create", { master: "doce-chars!!" });
    assert.deepEqual(await w.call("changePassword", { current: "doce-chars!!", next: "corta-11ch!" }), { ok: false, error: "BAD_REQUEST" });
  });

  test("password changed on another device → KEYRING_CHANGED; adopt with wrong password fails, right one merges and resumes", async () => {
    const { remote, a, b } = await pair();
    await a.ok("changePassword", { current: MASTER, next: NEW_MASTER });
    await a.ok("sync.now");
    await b.ok("createEntry", { input: { title: "Solo B", username: "b", password: "secret-from-device-b", urls: [], notes: "" } });

    assert.deepEqual(await b.call("sync.now"), { ok: false, error: "KEYRING_CHANGED" });
    const st = await b.ok<SyncStatusView>("sync.status");
    assert.equal(st.keysChanged, true);
    assert.equal(st.lastError, "KEYRING_CHANGED");
    assert.equal(typeof b.session.data.get("sync.pendingRemoteKeys"), "string", "remote container kept in storage.session");
    const before = b.local.data.get(KEYS.container);

    assert.deepEqual(await b.call("sync.adoptRemoteKeys", { master: "contraseña equivocada" }), { ok: false, error: "INVALID_CREDENTIALS" });
    assert.deepEqual(await b.call("sync.adoptRemoteKeys", { master: MASTER }), { ok: false, error: "INVALID_CREDENTIALS" }, "the old password does not open the new keys");
    assert.equal(b.local.data.get(KEYS.container), before, "nothing changed on failure");

    const r = await b.ok<AdoptResult>("sync.adoptRemoteKeys", { master: NEW_MASTER });
    assert.equal(typeof r.kdfWeakened, "boolean");
    assert.equal(r.sync.keysChanged, false);
    assert.equal(r.sync.lastError, null);
    assert.equal(b.session.data.has("sync.pendingRemoteKeys"), false);
    // B's local entry was merged and uploaded; A receives it without any prompt.
    await a.ok("sync.now");
    const titles = (await a.ok<EntrySummary[]>("list")).map((e) => e.title).sort();
    assert.deepEqual(titles, ["Desde A", "Solo B"]);
    // B now unlocks with the new password only.
    await b.ok("lock");
    assert.equal((await b.call("unlock", { master: MASTER })).ok, false);
    await b.ok("unlock", { master: NEW_MASTER });
    assert.ok(remote.revisionCount >= 3);
  });

  test("rotateDataKey: new recovery key, session DEK refreshed, old DEK cannot open the new container", async () => {
    const { w, recoveryKey } = await created();
    await w.ok("createEntry", { input: { title: "X", username: "", password: "secret-before-rotation", urls: [], notes: "" } });
    const oldDek = w.session.data.get(KEYS.dek) as string;
    assert.deepEqual(await w.call("rotateDataKey", { current: "no es la buena" }), { ok: false, error: "INVALID_CREDENTIALS" });
    const { recoveryKey: rk2 } = await w.ok<{ recoveryKey: string }>("rotateDataKey", { current: MASTER });
    assert.match(rk2, /^[A-Z2-7]{4}(-[A-Z2-7]{4}){13}$/);
    assert.notEqual(rk2, recoveryKey);
    const newDek = w.session.data.get(KEYS.dek) as string;
    assert.notEqual(newDek, oldDek, "storage.session holds the new DEK");
    const container = w.local.data.get(KEYS.container) as string;
    assert.throws(() => w.core.openWithDataKey(container, base64ToBytes(oldDek), "probe"), /INVALID_CREDENTIALS|INTEGRITY_ERROR/);
    const reopened = w.core.openWithDataKey(container, base64ToBytes(newDek), "probe");
    assert.equal(reopened.listEntries().length, 1);
    reopened.lock();
    reopened.free();
    assert.throws(() => w.core.unlockWithRecoveryKey(container, recoveryKey, "probe"), /INVALID_CREDENTIALS/);
    // A restarted service worker reopens with the refreshed session DEK.
    const w2 = worker({ local: w.local, session: w.session, clock: w.clock });
    assert.equal((await w2.ok<EntrySummary[]>("list")).length, 1);
  });

  test("data key rotated on another device: the other device re-authenticates once and its session DEK changes", async () => {
    const { a, b } = await pair();
    await a.ok("rotateDataKey", { current: MASTER });
    await a.ok("sync.now");
    const dekBefore = b.session.data.get(KEYS.dek);
    assert.deepEqual(await b.call("sync.now"), { ok: false, error: "KEYRING_CHANGED" });
    // After a lock the pending container is gone from storage.session: adopt reads the remote head again.
    await b.ok("lock");
    await b.ok("unlock", { master: MASTER });
    await b.ok("sync.adoptRemoteKeys", { master: MASTER });
    assert.notEqual(b.session.data.get(KEYS.dek), dekBefore);
    const w2 = worker({ local: b.local, session: b.session, clock: b.clock, deviceId: "device-b" });
    assert.deepEqual((await w2.ok<EntrySummary[]>("list")).map((e) => e.title), ["Desde A"]);
    assert.equal((await b.ok<SyncStatusView>("sync.status")).keysChanged, false);
  });
});
