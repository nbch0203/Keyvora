// Remote store contract shared with Android (docs/CONTRACTS.md §6).

export interface RemoteMeta {
  fileId: string;
  headRevisionId: string;
  modifiedTime: string;
  size: number;
}

export interface RevisionInfo {
  id: string;
  modifiedTime: string;
  size: number;
}

export interface RemoteStore {
  getMetadata(): Promise<RemoteMeta | null>;
  download(fileId: string): Promise<{ content: string; headRevisionId: string }>;
  create(content: string): Promise<RemoteMeta>;
  update(fileId: string, content: string): Promise<RemoteMeta>;
  /** Chronological order (oldest first). */
  listRevisions(fileId: string): Promise<RevisionInfo[]>;
  downloadRevision(fileId: string, revisionId: string): Promise<string>;
}

export type RemoteErrorCode = "NETWORK" | "AUTH_REQUIRED" | "RATE_LIMITED" | "REMOTE_ERROR";

/** Transport error. `message` is the code; no response bodies, URLs or tokens are kept. */
export class RemoteError extends Error {
  readonly code: RemoteErrorCode;
  readonly retryAfterMs: number | undefined;
  constructor(code: RemoteErrorCode, retryAfterMs?: number) {
    super(code);
    this.name = "RemoteError";
    this.code = code;
    this.retryAfterMs = retryAfterMs;
  }
}

export function isRetryable(code: string): boolean {
  return code === "NETWORK" || code === "RATE_LIMITED";
}
