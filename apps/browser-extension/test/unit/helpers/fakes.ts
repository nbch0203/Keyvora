// Test doubles: alarms, clock, and a CRDT-like vault for SyncEngine protocol tests (no crypto involved).
import type { MergeReport } from "../../../src/core/types.ts";
import type { SyncVault } from "../../../src/sync/engine.ts";

export class FakeAlarms {
  readonly alarms = new Map<string, number>();
  readonly delayed = new Map<string, number>();
  create(name: string, info: { when?: number; delayInMinutes?: number }): void {
    if (info.when !== undefined) this.alarms.set(name, info.when);
    if (info.delayInMinutes !== undefined) this.delayed.set(name, info.delayInMinutes);
  }
  clear(name: string): boolean {
    const had = this.alarms.delete(name) || this.delayed.delete(name);
    return had;
  }
}

export class FakeClock {
  t: number;
  constructor(start = Date.UTC(2026, 10, 15, 10, 0, 0)) {
    this.t = start;
  }
  now = (): number => this.t;
  advance(ms: number): void {
    this.t += ms;
  }
}

interface Rec {
  value: string;
  ver: number;
}

interface FakeContainer {
  format: "keyvora.vault";
  vaultId: string;
  revision: number;
  keyring?: number;
  entries: Record<string, Rec>;
}

/**
 * Minimal model of the core's merge semantics, enough to exercise the sync protocol: per-key records with a version
 * (higher wins, ties broken deterministically), `adoptedRemote` when the merge result equals the remote state.
 */
export class FakeSyncVault implements SyncVault {
  vaultId: string;
  revision = 0;
  /** Models keyringRevision: newer remote keys are never adopted by mergeRemote (KEYRING_CHANGED). */
  keyring = 1;
  dirty = false;
  entries: Record<string, Rec> = {};
  exports = 0;
  merges = 0;

  constructor(vaultId = "vault-1") {
    this.vaultId = vaultId;
  }

  set(key: string, value: string): void {
    const ver = (this.entries[key]?.ver ?? 0) + 1;
    this.entries[key] = { value, ver };
    this.dirty = true;
  }

  get(key: string): string | undefined {
    return this.entries[key]?.value;
  }

  containerNow(): string {
    if (this.dirty) {
      this.revision += 1;
      this.dirty = false;
    }
    const c: FakeContainer = { format: "keyvora.vault", vaultId: this.vaultId, revision: this.revision, keyring: this.keyring, entries: structuredClone(this.entries) };
    return JSON.stringify(c);
  }

  async exportContainer(): Promise<string> {
    this.exports++;
    return this.containerNow();
  }

  async mergeRemote(container: string): Promise<MergeReport> {
    this.merges++;
    let remote: FakeContainer;
    try {
      remote = JSON.parse(container) as FakeContainer;
    } catch {
      throw new Error("INVALID_FORMAT");
    }
    if (remote.vaultId !== this.vaultId) throw new Error("VAULT_MISMATCH");
    if ((remote.keyring ?? 1) > this.keyring) throw new Error("KEYRING_CHANGED");
    const merged: Record<string, Rec> = structuredClone(this.entries);
    let added = 0;
    let updated = 0;
    for (const [k, r] of Object.entries(remote.entries)) {
      const l = merged[k];
      if (!l) {
        merged[k] = { ...r };
        added++;
      } else if (r.ver > l.ver || (r.ver === l.ver && r.value > l.value)) {
        merged[k] = { ...r };
        updated++;
      }
    }
    const sameAsRemote = JSON.stringify(sortKeys(merged)) === JSON.stringify(sortKeys(remote.entries));
    const adopted = sameAsRemote && remote.revision >= this.revision && (remote.keyring ?? 1) === this.keyring;
    this.entries = merged;
    if (adopted) {
      this.revision = remote.revision;
      this.dirty = false;
    } else {
      this.revision = Math.max(this.revision, remote.revision);
      this.dirty = true;
    }
    return {
      remoteRevision: remote.revision,
      adoptedRemote: adopted,
      needsUpload: !adopted,
      added,
      updated,
      removed: 0,
      newConflicts: [],
      keyringAdopted: false,
      keyringConflict: false,
      kdfWeakened: false,
      recoveryKeyChanged: false,
    };
  }

  /** Models adoptRemoteKeys after the user re-authenticated. */
  async adoptKeys(container: string): Promise<MergeReport> {
    this.keyring = Math.max(this.keyring, (JSON.parse(container) as FakeContainer).keyring ?? 1);
    const r = await this.mergeRemote(container);
    return { ...r, keyringAdopted: true };
  }
}

function sortKeys(o: Record<string, Rec>): Array<[string, Rec]> {
  return Object.entries(o).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
}

/** Builds a fake container directly (e.g. an old revision for rollback tests). */
export function fakeContainer(vaultId: string, revision: number, entries: Record<string, Rec>, keyring = 1): string {
  return JSON.stringify({ format: "keyvora.vault", vaultId, revision, keyring, entries } satisfies FakeContainer);
}
