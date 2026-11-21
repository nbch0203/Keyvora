// QA-004: SYNC_PROTOCOL §3 scenarios not covered by sync-engine.test.ts, run against the REAL WASM core (two devices,
// real encrypted containers) through SyncEngine + InMemoryRemoteStore. Defect reproductions run only with
// KEYVORA_QA_RUN_DEFECTS=1 (see docs/QA_REPORT.md §5).
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type { CoreModule, CoreVault, EntryInput } from "../../src/core/types.ts";
import { SyncEngine, type SyncState } from "../../src/sync/engine.ts";
import { InMemoryRemoteStore } from "../../src/sync/in-memory.ts";
import { FAST_KDF, loadRealCore, SKIP_NO_CORE, withFastKdf } from "./helpers/core.ts";

const real = await loadRealCore();
const skip = real ? false : SKIP_NO_CORE;
const RUN_DEFECTS = process.env["KEYVORA_QA_RUN_DEFECTS"] === "1";
const MASTER = "contraseña maestra de QA";
const T0 = Date.UTC(2026, 10, 15, 12);

function entry(title: string, password: string): EntryInput {
  return { title, username: "qa@example.com", password, urls: ["https://example.com"], notes: "" };
}

interface Device {
  vault: CoreVault;
  engine: SyncEngine;
  state: () => SyncState | undefined;
  sleeps: number[];
  pendingKeys: string[];
}

function device(vault: CoreVault, remote: InMemoryRemoteStore): Device {
  let saved: SyncState | undefined;
  const sleeps: number[] = [];
  const pendingKeys: string[] = [];
  const engine = new SyncEngine(
    remote,
    { exportContainer: async () => vault.exportContainer(), mergeRemote: async (c) => vault.mergeRemote(c) },
    { load: async () => saved as SyncState, save: async (s) => void (saved = structuredClone(s)) },
    { sleep: async (ms) => void sleeps.push(ms), random: () => 0.5, now: () => T0, onKeysChanged: (c) => void pendingKeys.push(c) },
  );
  return { vault, engine, state: () => saved, sleeps, pendingKeys };
}

/** Device A creates the vault with one entry and uploads it; device B joins from Drive. */
async function twoDevices(core: CoreModule) {
  const remote = new InMemoryRemoteStore();
  const va = core.create(MASTER, FAST_KDF, "device-a", T0);
  va.takeRecoveryKey();
  va.createEntry(entry("Inicial", "pw-inicial"), T0);
  const a = device(va, remote);
  assert.equal((await a.engine.sync()).status, "created");
  const b = device(core.unlockWithPassword(remote.headContent!, MASTER, "device-b"), remote);
  await b.engine.sync();
  return { remote, a, b };
}

/** Titles visible in what Drive holds now (decrypted with a third, independent session). */
function remoteTitles(core: CoreModule, remote: InMemoryRemoteStore, master = MASTER): string[] {
  const probe = core.unlockWithPassword(remote.headContent!, master, "probe");
  try {
    return probe.listEntries().map((e) => e.title).sort();
  } finally {
    probe.lock();
    probe.free();
  }
}

function titles(v: CoreVault): string[] {
  return v.listEntries().map((e) => e.title).sort();
}

describe("QA-004 sync concurrency with the real core", { skip }, () => {
  const core = withFastKdf(real!);

  test("upload fails before reaching Drive, another device writes before the retry → retry merges it, nothing lost", async () => {
    const { remote, a, b } = await twoDevices(core);
    a.vault.createEntry(entry("Solo A", "pw-a"), T0 + 1);
    await a.engine.markDirty();
    b.vault.createEntry(entry("Solo B", "pw-b"), T0 + 2);
    await b.engine.markDirty();
    remote.failNext("update", "NETWORK");
    let injected = false;
    remote.beforeOp = async (op) => {
      // A's first upload attempt failed; while A backs off, B syncs (its upload lands on Drive).
      if (op === "getMetadata" && a.sleeps.length === 1 && !injected) {
        injected = true;
        remote.beforeOp = null;
        await b.engine.sync();
      }
    };
    const r = await a.engine.sync();
    assert.equal(r.attempts, 2);
    assert.equal(r.status, "uploaded");
    assert.ok(injected, "B wrote between A's attempts");
    assert.deepEqual(remoteTitles(core, remote), ["Inicial", "Solo A", "Solo B"]);
    await b.engine.sync();
    assert.deepEqual(titles(b.vault), ["Inicial", "Solo A", "Solo B"]);
  });

  test("upload applied but reply lost, then a device that never saw it overwrites the head → retry restores both", async () => {
    const { remote, a, b } = await twoDevices(core);
    a.vault.createEntry(entry("Solo A", "pw-a"), T0 + 1);
    await a.engine.markDirty();
    // B prepares its container from the state before A's upload (it never sees A's write).
    b.vault.createEntry(entry("Solo B", "pw-b"), T0 + 2);
    const fromB = b.vault.exportContainer();
    remote.failNext("update", "NETWORK", { afterApply: true });
    remote.beforeOp = (op, s) => {
      if (op === "getMetadata" && a.sleeps.length === 1) {
        remote.beforeOp = null;
        s.writeAsOtherClient(fromB); // last-writer-wins on Drive: A's applied upload is no longer the head
      }
    };
    const r = await a.engine.sync();
    assert.equal(r.status, "uploaded");
    assert.deepEqual(remoteTitles(core, remote), ["Inicial", "Solo A", "Solo B"], "nothing lost on Drive");
    assert.equal(a.state()!.dirty, false);
  });

  test("rollback (an old revision restored as head): warning raised, newer local data kept and re-uploaded", async () => {
    const { remote, a } = await twoDevices(core);
    const old = remote.headContent!;
    a.vault.createEntry(entry("Nueva", "pw-nueva"), T0 + 1);
    await a.engine.markDirty();
    await a.engine.sync();
    const highest = a.state()!.highestRemoteRevision;
    remote.writeAsOtherClient(old);
    const r = await a.engine.sync();
    assert.equal(r.rollbackWarning, true);
    assert.equal(a.state()!.rollbackWarning, true);
    assert.ok(a.state()!.highestRemoteRevision >= highest);
    assert.deepEqual(remoteTitles(core, remote), ["Inicial", "Nueva"], "local data re-uploaded over the rollback");
  });

  test("tampered head: INTEGRITY_ERROR fails closed — no retries, no upload, local vault and dirty flag intact", async () => {
    const { remote, a } = await twoDevices(core);
    a.vault.createEntry(entry("Local", "pw-local"), T0 + 1);
    await a.engine.markDirty();
    const c = JSON.parse(remote.headContent!) as { payload: { ciphertext: string } };
    const ct = c.payload.ciphertext;
    c.payload.ciphertext = (ct[0] === "A" ? "B" : "A") + ct.slice(1);
    remote.writeAsOtherClient(JSON.stringify(c));
    remote.calls.length = 0;
    await assert.rejects(a.engine.sync(), /INTEGRITY_ERROR/);
    assert.equal(a.sleeps.length, 0);
    assert.ok(!remote.calls.includes("update"));
    assert.equal(a.state()!.dirty, true);
    assert.equal(a.state()!.lastError, "INTEGRITY_ERROR");
    assert.deepEqual(titles(a.vault), ["Inicial", "Local"]);
  });

  test("KEYRING_CHANGED found in an intermediate revision (password changed elsewhere during our upload) → stop, adopt, converge", async () => {
    const { remote, a, b } = await twoDevices(core);
    const NEW = "violeta tranvía helecho brújula 47";
    a.vault.createEntry(entry("Solo A", "pw-a"), T0 + 1);
    await a.engine.markDirty();
    b.vault.changeMasterPassword(MASTER, NEW, FAST_KDF, T0 + 1);
    b.vault.createEntry(entry("Solo B", "pw-b"), T0 + 2);
    const fromB = b.vault.exportContainer();
    let injected = false;
    remote.beforeOp = (op, s) => {
      // B uploads after A's pre-check and before A's write (no atomic If-Match on Drive).
      if (op === "update" && !injected) {
        injected = true;
        s.writeAsOtherClient(fromB);
      }
    };
    await assert.rejects(a.engine.sync(), /KEYRING_CHANGED/);
    remote.beforeOp = null;
    assert.equal(a.state()!.keysChanged, true);
    assert.equal(a.state()!.dirty, true);
    assert.deepEqual(a.pendingKeys, [fromB], "the container with the new keys is handed to the UI");
    assert.deepEqual(titles(a.vault), ["Inicial", "Solo A"], "nothing merged before re-authentication");
    assert.throws(() => a.vault.adoptRemoteKeys(fromB, MASTER), /INVALID_CREDENTIALS/);
    const report = a.vault.adoptRemoteKeys(fromB, NEW);
    await a.engine.keysAdopted(report.needsUpload);
    await a.engine.sync();
    assert.deepEqual(remoteTitles(core, remote, NEW), ["Inicial", "Solo A", "Solo B"]);
    // B converges and A's head (new keys) opens only with the new password.
    await b.engine.sync();
    assert.deepEqual(titles(b.vault), ["Inicial", "Solo A", "Solo B"]);
    assert.throws(() => core.unlockWithPassword(remote.headContent!, MASTER, "probe"), /INVALID_CREDENTIALS/);
  });

  test(
    "QA-DEF-003: data key rotated on both devices while offline → both converge (fixed: KEYRING_CHANGED + re-authentication)",
    {},
    async () => {
      const { remote, a, b } = await twoDevices(core);
      a.vault.rotateDataKey(MASTER);
      a.vault.takeRecoveryKey();
      b.vault.rotateDataKey(MASTER);
      b.vault.takeRecoveryKey();
      await a.engine.markDirty();
      await b.engine.markDirty();
      await a.engine.sync();
      const errors: string[] = [];
      for (let i = 0; i < 3; i++) {
        for (const d of [b, a]) {
          try {
            await d.engine.sync();
          } catch (e) {
            const code = (e as Error).message;
            if (code === "KEYRING_CHANGED") {
              const r = d.vault.adoptRemoteKeys(d.pendingKeys.at(-1)!, MASTER);
              await d.engine.keysAdopted(r.needsUpload);
            } else errors.push(code);
          }
        }
      }
      assert.deepEqual(errors, [], "sync must not stay blocked");
      assert.deepEqual(titles(a.vault), titles(b.vault));
      assert.ok(remote.revisionCount > 0);
    },
  );
});
