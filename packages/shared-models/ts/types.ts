// Shapes of the values exchanged with the Keyvora core (WASM). Contract v1 — docs/CONTRACTS.md §2.
// The extension must use these types; do not duplicate core logic in TypeScript.

export type ErrorCode =
  | "INVALID_FORMAT"
  | "UNSUPPORTED_VERSION"
  | "PARAMS_OUT_OF_BOUNDS"
  | "INVALID_CREDENTIALS"
  | "INVALID_RECOVERY_KEY"
  | "INTEGRITY_ERROR"
  | "VAULT_MISMATCH"
  | "KEYRING_CHANGED"
  | "NOT_FOUND"
  | "VALIDATION"
  | "LOCKED"
  | "CRYPTO";

export interface KdfParams {
  memoryKiB: number;
  iterations: number;
  parallelism: number;
}

export interface EntryInput {
  title: string;
  username: string;
  password: string;
  urls: string[];
  notes: string;
}

export interface EntrySummary {
  id: string;
  title: string;
  username: string;
  urls: string[];
  updatedAt: string; // YYYY-MM-DDTHH:MM:SS.sssZ
  hasConflicts: boolean;
}

export interface HistoryItem {
  password: string;
  retiredAt: string;
}

export interface ConflictSnapshot {
  kind: "edit" | "deletion";
  title: string;
  username: string;
  password: string;
  urls: string[];
  notes: string;
  updatedAt: string;
  updatedBy: string;
}

export interface Entry extends Omit<EntrySummary, "hasConflicts"> {
  password: string;
  notes: string;
  createdAt: string;
  updatedBy: string;
  passwordHistory: HistoryItem[];
  conflicts: ConflictSnapshot[];
}

export type MatchLevel = "exact" | "sameSite" | "none";

export interface CredentialMatch {
  entry: EntrySummary;
  level: Exclude<MatchLevel, "none">;
  matchedUrl: string;
  pageHost: string;
  pageIsIdn: boolean;
}

export interface MergeReport {
  remoteRevision: number;
  adoptedRemote: boolean;
  needsUpload: boolean;
  added: number;
  updated: number;
  removed: number;
  newConflicts: string[];
  keyringAdopted: boolean;
  keyringConflict: boolean;
  /** Adopted master-password KDF parameters are weaker than before or than the defaults: warn the user. */
  kdfWeakened: boolean;
  /** The recovery key shown earlier on this device no longer opens the vault: tell the user, offer a new one. */
  recoveryKeyChanged: boolean;
}

export interface GeneratorOptions {
  length?: number; // 8..128, default 20
  lowercase?: boolean;
  uppercase?: boolean;
  digits?: boolean;
  symbols?: boolean;
  excludeAmbiguous?: boolean;
  requireEachClass?: boolean;
}

/** Instance API of the generated `WasmVault` class (wasm-bindgen, target `web`). */
export interface CoreVault {
  takeRecoveryKey(): string | undefined;
  exportContainer(): string;
  vaultId(): string;
  revision(): number;
  isDirty(): boolean;
  isLocked(): boolean;
  listEntries(): EntrySummary[];
  search(query: string): EntrySummary[];
  getEntry(id: string): Entry;
  createEntry(input: EntryInput, nowMs: number): Entry;
  updateEntry(id: string, input: EntryInput, nowMs: number): Entry;
  deleteEntry(id: string, nowMs: number): void;
  /** -1 keeps the current version; n >= 0 takes conflict n */
  resolveConflict(id: string, choice: number, nowMs: number): void;
  findMatches(pageUrl: string): CredentialMatch[];
  /**
   * Also rotates the data key and issues a new recovery key (read it once with takeRecoveryKey(); the old one stops
   * working). Throws VALIDATION when the new password is too short, too weak or reused.
   */
  changeMasterPassword(current: string, next: string, params: KdfParams, nowMs: number): void;
  /** Same as changeMasterPassword, proving the recovery key instead (which is replaced by a new one). */
  resetMasterPasswordWithRecovery(recoveryKey: string, next: string, params: KdfParams, nowMs: number): void;
  rotateRecoveryKey(current: string): void;
  /** New data key + new recovery key (read it once with takeRecoveryKey()). Old secrets stop opening new data. */
  rotateDataKey(current: string): void;
  passwordKdfParams(): KdfParams;
  /** Throws KEYRING_CHANGED when the remote keys are newer: then ask for the master password and call adoptRemoteKeys. */
  mergeRemote(remoteContainer: string): MergeReport;
  /** Re-authenticates with the master password valid for the remote container and adopts its keys, merging local data. */
  adoptRemoteKeys(remoteContainer: string, master: string): MergeReport;
  restoreEntriesFrom(container: string, ids: string[], nowMs: number): Entry[];
  previewContainer(container: string): EntrySummary[];
  exportDataKey(): Uint8Array;
  lock(): void;
  free(): void;
}

/** Static/free functions of the WASM module. */
export interface CoreModule {
  create(master: string, params: KdfParams, deviceId: string, nowMs: number): CoreVault;
  unlockWithPassword(container: string, master: string, deviceId: string): CoreVault;
  unlockWithRecoveryKey(container: string, recoveryKey: string, deviceId: string): CoreVault;
  openWithDataKey(container: string, dek: Uint8Array, deviceId: string): CoreVault;
  generatePassword(options?: GeneratorOptions): string;
  passwordEntropyBits(options?: GeneratorOptions): number;
  matchLevel(entryUrl: string, pageUrl: string): MatchLevel;
  pageOrigin(pageUrl: string): string | undefined;
  defaultKdfParams(): KdfParams;
  benchmarkKdf(params: KdfParams): void;
}

/** Errors thrown by the core carry exactly one ErrorCode as `message`. */
export function errorCode(e: unknown): ErrorCode | "UNKNOWN" {
  const m = e instanceof Error ? e.message : String(e);
  const codes: ErrorCode[] = [
    "INVALID_FORMAT", "UNSUPPORTED_VERSION", "PARAMS_OUT_OF_BOUNDS", "INVALID_CREDENTIALS", "INVALID_RECOVERY_KEY",
    "INTEGRITY_ERROR", "VAULT_MISMATCH", "KEYRING_CHANGED", "NOT_FOUND", "VALIDATION", "LOCKED", "CRYPTO",
  ];
  return (codes as string[]).includes(m) ? (m as ErrorCode) : "UNKNOWN";
}
