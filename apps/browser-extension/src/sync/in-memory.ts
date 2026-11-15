// In-memory RemoteStore with Drive-like semantics for tests: revision history, injectable failures and a hook
// that lets a test act as another client between operations (interleaving).
import { RemoteError, type RemoteErrorCode, type RemoteMeta, type RemoteStore, type RevisionInfo } from "./types.ts";

export type RemoteOp = "getMetadata" | "download" | "create" | "update" | "listRevisions" | "downloadRevision";

interface StoredRevision {
  id: string;
  content: string;
  modifiedTime: string;
}

interface Failure {
  op: RemoteOp;
  code: RemoteErrorCode;
  /** The operation takes effect on the "server" but the reply is lost. Only meaningful for create/update. */
  afterApply: boolean;
  remaining: number;
  retryAfterMs?: number | undefined;
}

export class InMemoryRemoteStore implements RemoteStore {
  readonly fileId = "file-1";
  /** Every operation invoked, in order. */
  readonly calls: RemoteOp[] = [];
  /** Called before each operation; may call `writeAsOtherClient` to simulate a concurrent writer. */
  beforeOp: ((op: RemoteOp, store: InMemoryRemoteStore) => void | Promise<void>) | null = null;

  #revisions: StoredRevision[] = [];
  #exists = false;
  #seq = 0;
  #clock: number;
  #failures: Failure[] = [];
  #purged = new Set<string>();

  constructor(startTimeMs = Date.UTC(2026, 10, 15)) {
    this.#clock = startTimeMs;
  }

  /** Injects a failure for the next `times` calls of `op`. */
  failNext(op: RemoteOp, code: RemoteErrorCode, opts: { times?: number; afterApply?: boolean; retryAfterMs?: number } = {}): void {
    this.#failures.push({ op, code, afterApply: opts.afterApply ?? false, remaining: opts.times ?? 1, retryAfterMs: opts.retryAfterMs });
  }

  /** Writes a new head revision as another client would (creates the file if needed). */
  writeAsOtherClient(content: string): RemoteMeta {
    this.#exists = true;
    return this.#append(content);
  }

  /** Simulates Drive purging an old revision. */
  purgeRevision(id: string): void {
    this.#purged.add(id);
  }

  /** Deletes the remote file (user removed hidden app data). */
  deleteFile(): void {
    this.#exists = false;
    this.#revisions = [];
  }

  get headContent(): string | null {
    return this.#exists ? (this.#revisions.at(-1)?.content ?? null) : null;
  }

  get revisionCount(): number {
    return this.#revisions.length;
  }

  #append(content: string): RemoteMeta {
    this.#clock += 1000;
    const rev: StoredRevision = { id: `rev-${++this.#seq}`, content, modifiedTime: new Date(this.#clock).toISOString() };
    this.#revisions.push(rev);
    return this.#meta();
  }

  #meta(): RemoteMeta {
    const head = this.#revisions.at(-1);
    if (!head) throw new RemoteError("REMOTE_ERROR");
    return { fileId: this.fileId, headRevisionId: head.id, modifiedTime: head.modifiedTime, size: head.content.length };
  }

  async #enter(op: RemoteOp): Promise<Failure | null> {
    this.calls.push(op);
    if (this.beforeOp) await this.beforeOp(op, this);
    const i = this.#failures.findIndex((f) => f.op === op);
    if (i === -1) return null;
    const f = this.#failures[i]!;
    f.remaining -= 1;
    if (f.remaining <= 0) this.#failures.splice(i, 1);
    if (!f.afterApply) throw new RemoteError(f.code, f.retryAfterMs);
    return f;
  }

  #checkFile(fileId: string): void {
    if (!this.#exists || fileId !== this.fileId) throw new RemoteError("REMOTE_ERROR");
  }

  async getMetadata(): Promise<RemoteMeta | null> {
    await this.#enter("getMetadata");
    return this.#exists ? this.#meta() : null;
  }

  async download(fileId: string): Promise<{ content: string; headRevisionId: string }> {
    await this.#enter("download");
    this.#checkFile(fileId);
    const head = this.#revisions.at(-1)!;
    return { content: head.content, headRevisionId: head.id };
  }

  async create(content: string): Promise<RemoteMeta> {
    const f = await this.#enter("create");
    this.#exists = true;
    this.#revisions = [];
    const meta = this.#append(content);
    if (f) throw new RemoteError(f.code, f.retryAfterMs);
    return meta;
  }

  async update(fileId: string, content: string): Promise<RemoteMeta> {
    const f = await this.#enter("update");
    this.#checkFile(fileId);
    const meta = this.#append(content);
    if (f) throw new RemoteError(f.code, f.retryAfterMs);
    return meta;
  }

  async listRevisions(fileId: string): Promise<RevisionInfo[]> {
    await this.#enter("listRevisions");
    this.#checkFile(fileId);
    return this.#revisions
      .filter((r) => !this.#purged.has(r.id))
      .map((r) => ({ id: r.id, modifiedTime: r.modifiedTime, size: r.content.length }));
  }

  async downloadRevision(fileId: string, revisionId: string): Promise<string> {
    await this.#enter("downloadRevision");
    this.#checkFile(fileId);
    const r = this.#revisions.find((x) => x.id === revisionId && !this.#purged.has(x.id));
    if (!r) throw new RemoteError("REMOTE_ERROR");
    return r.content;
  }
}
