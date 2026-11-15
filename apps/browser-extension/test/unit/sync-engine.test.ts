import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { backoffDelay, containerRevision, intermediateRevisions, SyncEngine, type SyncState } from "../../src/sync/engine.ts";
import { InMemoryRemoteStore } from "../../src/sync/in-memory.ts";
import { fakeContainer, FakeSyncVault } from "./helpers/fakes.ts";

function memoryStateStore() {
  let saved: SyncState | undefined;
  return {
    store: { load: async () => saved as SyncState, save: async (s: SyncState) => void (saved = structuredClone(s)) },
    get: () => saved,
  };
}

function device(remote: InMemoryRemoteStore, vault = new FakeSyncVault()) {
  const st = memoryStateStore();
  const sleeps: number[] = [];
  const pendingKeys: string[] = [];
  const engine = new SyncEngine(remote, vault, st.store, {
    sleep: async (ms) => void sleeps.push(ms),
    random: () => 0.5,
    now: () => 1_000,
    onKeysChanged: (c) => void pendingKeys.push(c),
  });
  return { vault, engine, state: st.get, sleeps, pendingKeys };
}

function remoteEntries(remote: InMemoryRemoteStore): Record<string, { value: string }> {
  return (JSON.parse(remote.headContent!) as { entries: Record<string, { value: string }> }).entries;
}

describe("SyncEngine (SYNC_PROTOCOL §3) with InMemoryRemoteStore", () => {
  test("first upload creates the remote file", async () => {
    const remote = new InMemoryRemoteStore();
    const a = device(remote);
    a.vault.set("github", "pw1");
    const r = await a.engine.sync();
    assert.equal(r.status, "created");
    assert.deepEqual(remote.calls, ["getMetadata", "create"]);
    assert.equal(remoteEntries(remote)["github"]!.value, "pw1");
    assert.equal(a.state()!.lastSyncedHeadRevisionId, "rev-1");
    assert.equal(a.state()!.dirty, false);
    assert.equal(a.state()!.highestRemoteRevision, 1);
  });

  test("up to date: only metadata is read", async () => {
    const remote = new InMemoryRemoteStore();
    const a = device(remote);
    a.vault.set("k", "v");
    await a.engine.sync();
    remote.calls.length = 0;
    const r = await a.engine.sync();
    assert.equal(r.status, "up-to-date");
    assert.deepEqual(remote.calls, ["getMetadata"]);
  });

  test("remote newer: download and merge, no upload", async () => {
    const remote = new InMemoryRemoteStore();
    const a = device(remote);
    const b = device(remote);
    a.vault.set("a", "1");
    await a.engine.sync();
    await b.engine.sync(); // B adopts A's vault
    b.vault.set("b", "2");
    await b.engine.markDirty();
    await b.engine.sync();
    remote.calls.length = 0;
    const r = await a.engine.sync();
    assert.equal(r.status, "merged");
    assert.equal(a.vault.get("b"), "2");
    assert.ok(!remote.calls.includes("update") && !remote.calls.includes("create"));
    assert.equal(a.state()!.dirty, false);
  });

  test("local changes are merged with the latest remote before upload", async () => {
    const remote = new InMemoryRemoteStore();
    const a = device(remote);
    const b = device(remote);
    a.vault.set("a", "1");
    await a.engine.sync();
    await b.engine.sync();
    b.vault.set("b", "2");
    await b.engine.markDirty();
    await b.engine.sync();
    a.vault.set("a2", "3");
    await a.engine.markDirty();
    const r = await a.engine.sync();
    assert.equal(r.status, "uploaded");
    const e = remoteEntries(remote);
    assert.deepEqual(Object.keys(e).sort(), ["a", "a2", "b"]);
    const i = remote.calls.lastIndexOf("download");
    assert.deepEqual(remote.calls.slice(i), ["download", "getMetadata", "update", "listRevisions"], "merge → pre-check → upload → revision check");
  });

  test("local change with an unchanged remote head: uploads without re-downloading the revision already merged", async () => {
    const remote = new InMemoryRemoteStore();
    const a = device(remote);
    a.vault.set("a", "1");
    await a.engine.sync();
    a.vault.set("a", "2");
    await a.engine.markDirty();
    remote.calls.length = 0;
    const r = await a.engine.sync();
    assert.equal(r.status, "uploaded");
    assert.deepEqual(remote.calls, ["getMetadata", "getMetadata", "update", "listRevisions"]);
    assert.equal(remoteEntries(remote)["a"]!.value, "2");
  });

  test("concurrent write interleaved right before our upload is detected and merged (no loss)", async () => {
    const remote = new InMemoryRemoteStore();
    const a = device(remote);
    const c = new FakeSyncVault();
    a.vault.set("a", "1");
    await a.engine.sync();
    await c.mergeRemote(remote.headContent!);
    c.set("c", "from-C");
    const cContainer = c.containerNow();
    a.vault.set("a", "2");
    await a.engine.markDirty();
    let injected = false;
    remote.beforeOp = (op, s) => {
      // C uploads after A's headRevisionId pre-check and before A's write: Drive has no atomic If-Match.
      if (op === "update" && !injected) {
        injected = true;
        s.writeAsOtherClient(cContainer);
      }
    };
    const r = await a.engine.sync();
    assert.equal(r.status, "uploaded");
    assert.equal(r.rounds, 2, "second round re-uploads after merging the intermediate revision");
    assert.equal(a.vault.get("c"), "from-C", "intermediate revision merged locally");
    const e = remoteEntries(remote);
    assert.equal(e["c"]!.value, "from-C", "C's change is in the final head");
    assert.equal(e["a"]!.value, "2", "A's change is in the final head");
    assert.equal(a.state()!.dirty, false);
    assert.ok(remote.calls.includes("downloadRevision"));
  });

  test("a write between our download and the pre-check starts a new round", async () => {
    const remote = new InMemoryRemoteStore();
    const a = device(remote);
    const c = new FakeSyncVault();
    a.vault.set("a", "1");
    await a.engine.sync();
    await c.mergeRemote(remote.headContent!);
    c.set("c", "x");
    const cc = c.containerNow();
    a.vault.set("a", "2");
    await a.engine.markDirty();
    let metaCalls = 0;
    remote.beforeOp = (op, s) => {
      if (op === "getMetadata" && ++metaCalls === 2) s.writeAsOtherClient(cc);
    };
    const r = await a.engine.sync();
    assert.equal(r.status, "uploaded");
    assert.equal(r.rounds, 2);
    assert.deepEqual(Object.keys(remoteEntries(remote)).sort(), ["a", "c"]);
  });

  test("failure mid-upload (reply lost) then retry with backoff: idempotent, nothing lost", async () => {
    const remote = new InMemoryRemoteStore();
    const a = device(remote);
    const b = device(remote);
    a.vault.set("a", "1");
    await a.engine.sync();
    await b.engine.sync();
    b.vault.set("b", "1");
    await b.engine.markDirty();
    await b.engine.sync();
    a.vault.set("a", "2");
    await a.engine.markDirty();
    remote.failNext("update", "NETWORK", { afterApply: true });
    const r = await a.engine.sync();
    assert.equal(r.attempts, 2);
    assert.equal(a.sleeps.length, 1);
    assert.ok(a.sleeps[0]! >= 500 && a.sleeps[0]! <= 1000, `backoff ${a.sleeps[0]}`);
    const e = remoteEntries(remote);
    assert.equal(e["a"]!.value, "2");
    assert.equal(e["b"]!.value, "1");
    assert.equal(a.state()!.dirty, false);
    assert.equal(a.state()!.lastError, null);
  });

  test("failure before the upload reaches the server is retried", async () => {
    const remote = new InMemoryRemoteStore();
    const a = device(remote);
    a.vault.set("a", "1");
    await a.engine.sync();
    a.vault.set("a", "2");
    await a.engine.markDirty();
    remote.failNext("update", "RATE_LIMITED", { retryAfterMs: 5000 });
    const r = await a.engine.sync();
    assert.equal(r.status, "uploaded");
    assert.equal(a.sleeps[0], 5000, "Retry-After honored");
    assert.equal(remoteEntries(remote)["a"]!.value, "2");
  });

  test("retryable errors give up after the max attempts with exponential backoff", async () => {
    const remote = new InMemoryRemoteStore();
    const a = device(remote);
    a.vault.set("a", "1");
    remote.failNext("getMetadata", "NETWORK", { times: 10 });
    await assert.rejects(a.engine.sync(), /NETWORK/);
    assert.deepEqual(a.sleeps, [750, 1500, 3000, 6000]);
    assert.equal(a.state()!.lastError, "NETWORK");
    assert.equal(a.state()!.dirty, true, "offline: changes stay pending");
  });

  test("non-retryable errors surface immediately", async () => {
    const remote = new InMemoryRemoteStore();
    const a = device(remote);
    remote.failNext("getMetadata", "AUTH_REQUIRED");
    await assert.rejects(a.engine.sync(), /AUTH_REQUIRED/);
    assert.equal(a.sleeps.length, 0);
    assert.equal(a.state()!.lastError, "AUTH_REQUIRED");
  });

  test("rollback: remote revision lower than the highest seen → warning, merged anyway, local data kept", async () => {
    const remote = new InMemoryRemoteStore();
    const a = device(remote);
    a.vault.set("a", "1");
    await a.engine.sync();
    a.vault.set("b", "2");
    await a.engine.markDirty();
    await a.engine.sync();
    const highest = a.state()!.highestRemoteRevision;
    assert.ok(highest >= 2);
    // Someone restores an old copy (revision 1) as the head.
    remote.writeAsOtherClient(fakeContainer("vault-1", 1, { a: { value: "1", ver: 1 } }));
    const r = await a.engine.sync();
    assert.equal(r.rollbackWarning, true);
    assert.equal(a.state()!.rollbackWarning, true);
    assert.deepEqual(Object.keys(remoteEntries(remote)).sort(), ["a", "b"], "local data re-uploaded");
    await a.engine.acknowledgeRollback();
    assert.equal(a.state()!.rollbackWarning, false);
  });

  test("never ending concurrent writers → CONFLICT_RETRY_EXHAUSTED after 5 rounds, local data intact", async () => {
    const remote = new InMemoryRemoteStore();
    const a = device(remote);
    a.vault.set("a", "1");
    await a.engine.sync();
    a.vault.set("a", "2");
    await a.engine.markDirty();
    let n = 0;
    remote.beforeOp = (op, s) => {
      if (op === "getMetadata" && ++n % 2 === 0) s.writeAsOtherClient(fakeContainer("vault-1", 100 + n, { [`x${n}`]: { value: "w", ver: 1 } }));
    };
    await assert.rejects(a.engine.sync(), /CONFLICT_RETRY_EXHAUSTED/);
    assert.equal(a.state()!.lastError, "CONFLICT_RETRY_EXHAUSTED");
    assert.equal(a.state()!.dirty, true);
    assert.equal(a.vault.get("a"), "2");
    assert.ok(!remote.calls.includes("update"), "never uploaded without merging the latest head");
  });

  test("a local change made during a sync keeps the dirty flag", async () => {
    const remote = new InMemoryRemoteStore();
    const a = device(remote);
    a.vault.set("a", "1");
    await a.engine.sync();
    a.vault.set("a", "2");
    await a.engine.markDirty();
    let fired = false;
    remote.beforeOp = async (op) => {
      if (op === "listRevisions" && !fired) {
        fired = true;
        a.vault.set("late", "x");
        await a.engine.markDirty();
      }
    };
    const r = await a.engine.sync();
    remote.beforeOp = null;
    assert.ok(r.rounds >= 2 || a.state()!.dirty, "late change either uploaded in a later round or still pending");
    await a.engine.sync();
    assert.equal(remoteEntries(remote)["late"]!.value, "x");
  });

  test("a remote container of another vault fails closed (VAULT_MISMATCH) and nothing is uploaded", async () => {
    const remote = new InMemoryRemoteStore();
    remote.writeAsOtherClient(fakeContainer("other-vault", 3, {}));
    const a = device(remote);
    a.vault.set("a", "1");
    await assert.rejects(a.engine.sync(), /VAULT_MISMATCH/);
    assert.ok(!remote.calls.includes("update"));
    assert.equal(a.state()!.lastError, "VAULT_MISMATCH");
  });

  test("newer remote keys → KEYRING_CHANGED: stops without retries or upload, keeps the container, resumes after adoption", async () => {
    const remote = new InMemoryRemoteStore();
    const a = device(remote);
    a.vault.set("a", "1");
    await a.engine.sync();
    // Another device changed the master password / rotated the data key and uploaded (keyring 2).
    const other = new FakeSyncVault();
    await other.mergeRemote(remote.headContent!);
    other.keyring = 2;
    other.set("o", "from-other");
    const otherContainer = other.containerNow();
    remote.writeAsOtherClient(otherContainer);
    a.vault.set("a", "2");
    await a.engine.markDirty();
    remote.calls.length = 0;

    await assert.rejects(a.engine.sync(), /KEYRING_CHANGED/);
    assert.equal(a.sleeps.length, 0, "not retried");
    assert.ok(!remote.calls.includes("update"), "nothing uploaded");
    assert.equal(a.state()!.keysChanged, true);
    assert.equal(a.state()!.lastError, "KEYRING_CHANGED");
    assert.equal(a.state()!.dirty, true);
    assert.deepEqual(a.pendingKeys, [otherContainer]);
    assert.equal(a.vault.get("o"), undefined, "nothing merged before the user re-authenticates");
    await assert.rejects(a.engine.sync(), /KEYRING_CHANGED/, "stays stopped");

    const report = await a.vault.adoptKeys(a.pendingKeys.at(-1)!);
    await a.engine.keysAdopted(report.needsUpload);
    assert.equal(a.state()!.keysChanged, false);
    const r = await a.engine.sync();
    assert.equal(r.status, "uploaded");
    const e = remoteEntries(remote);
    assert.equal(e["a"]!.value, "2");
    assert.equal(e["o"]!.value, "from-other");
    assert.equal((JSON.parse(remote.headContent!) as { keyring: number }).keyring, 2);
    assert.equal(a.state()!.lastError, null);
  });

  test("concurrent sync() calls share one run", async () => {
    const remote = new InMemoryRemoteStore();
    const a = device(remote);
    a.vault.set("a", "1");
    const [r1, r2] = await Promise.all([a.engine.sync(), a.engine.sync()]);
    assert.equal(r1, r2);
    assert.equal(remote.calls.filter((c) => c === "create").length, 1);
  });
});

describe("sync helpers", () => {
  test("backoff: 1 s, 2 s, 4 s… capped at 60 s, jitter in [d/2, d]", () => {
    assert.equal(backoffDelay(0, 1000, 60_000, () => 0), 500);
    assert.equal(backoffDelay(0, 1000, 60_000, () => 1), 1000);
    assert.equal(backoffDelay(2, 1000, 60_000, () => 1), 4000);
    assert.equal(backoffDelay(10, 1000, 60_000, () => 1), 60_000);
    assert.equal(backoffDelay(0, 1000, 60_000, () => 0, 120_000), 60_000, "Retry-After capped");
  });
  test("containerRevision reads only the plaintext header", () => {
    assert.equal(containerRevision('{"revision": 12, "payload": {}}'), 12);
    assert.equal(containerRevision("nope"), null);
    assert.equal(containerRevision('{"revision": -1}'), null);
  });
  test("intermediateRevisions", () => {
    const revs = ["r1", "r2", "r3", "r4"].map((id, i) => ({ id, modifiedTime: `2026-01-0${i + 1}`, size: 1 }));
    assert.deepEqual(intermediateRevisions(revs, "r1", "r4", "2026-01-01").map((r) => r.id), ["r2", "r3"]);
    assert.deepEqual(intermediateRevisions(revs, "r3", "r4", "2026-01-03").map((r) => r.id), []);
    // `from` purged by Drive: fall back to modification time.
    assert.deepEqual(intermediateRevisions(revs.slice(1), "r1", "r4", "2026-01-02").map((r) => r.id), ["r2", "r3"]);
    // our upload not listed yet (eventual consistency): everything after `from`.
    assert.deepEqual(intermediateRevisions(revs.slice(0, 3), "r1", "r4", "2026-01-01").map((r) => r.id), ["r2", "r3"]);
  });
});
