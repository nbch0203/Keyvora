// Cross-platform vectors (packages/shared-models/test-vectors/vault-v1.json) against the real WASM core.
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { describe, test } from "node:test";
import { loadRealCore, SKIP_NO_CORE, VECTORS } from "./helpers/core.ts";

const core = await loadRealCore();
const vectors = existsSync(VECTORS) ? JSON.parse(readFileSync(VECTORS, "utf8")) : null;
const skip = !core ? SKIP_NO_CORE : !vectors ? `vectores ausentes (${VECTORS})` : false;

interface ExpectedEntry {
  title: string;
  username: string;
  password: string;
  urls: string[];
  notes: string;
}

describe("test vectors vault-v1.json", { skip }, () => {
  const v = vectors?.vault;
  const DEVICE = "ext-vector-test";

  function checkEntries(vault: { listEntries(): Array<{ id: string }>; getEntry(id: string): ExpectedEntry; lock(): void; free(): void }) {
    const got = vault.listEntries().map((s) => {
      const e = vault.getEntry(s.id);
      return { title: e.title, username: e.username, password: e.password, urls: e.urls, notes: e.notes };
    });
    const key = (e: ExpectedEntry) => e.title;
    assert.deepEqual([...got].sort((a, b) => key(a).localeCompare(key(b))), [...(v.expectedEntries as ExpectedEntry[])].sort((a, b) => key(a).localeCompare(key(b))));
    vault.lock();
    vault.free();
  }

  test("unlocks with the master password", () => {
    checkEntries(core!.unlockWithPassword(v.container, v.masterPassword, DEVICE) as never);
  });
  test("unlocks with the NFD variant of the master password (NFC normalization)", () => {
    assert.notEqual(v.masterPasswordNfdVariant, v.masterPassword);
    checkEntries(core!.unlockWithPassword(v.container, v.masterPasswordNfdVariant, DEVICE) as never);
  });
  test("unlocks with the recovery key", () => {
    checkEntries(core!.unlockWithRecoveryKey(v.container, v.recoveryKey, DEVICE) as never);
  });
  test("wrong password → INVALID_CREDENTIALS", () => {
    assert.throws(() => core!.unlockWithPassword(v.container, `${v.masterPassword}x`, DEVICE), /^Error: INVALID_CREDENTIALS$/);
  });
  test("reproduces every originMatching vector with matchLevel", () => {
    const list = vectors.originMatching as Array<{ entryUrl: string; pageUrl: string; expected: string }>;
    assert.ok(list.length > 0);
    for (const m of list) assert.equal(core!.matchLevel(m.entryUrl, m.pageUrl), m.expected, `${m.entryUrl} vs ${m.pageUrl}`);
  });
});
