// Google Drive API v3 RemoteStore over `fetch` (appDataFolder, scope drive.appdata). Only the encrypted
// container is ever uploaded. Errors are mapped to NETWORK | AUTH_REQUIRED | RATE_LIMITED | REMOTE_ERROR and never
// include response bodies, URLs or tokens.
import { RemoteError, type RemoteMeta, type RemoteStore, type RevisionInfo } from "./types.ts";

export const DRIVE_API = "https://www.googleapis.com/drive/v3";
export const DRIVE_UPLOAD_API = "https://www.googleapis.com/upload/drive/v3";
export const VAULT_FILE_NAME = "keyvora-vault.json";
export const META_FIELDS = "id,headRevisionId,modifiedTime,size";
/** Download cap: containers are ≤ 32 MiB (VAULT_FORMAT); anything bigger is refused before it fills memory (EXT-SEC-4). */
export const MAX_DOWNLOAD_BYTES = 40 * 1024 * 1024;

export type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

export interface TokenProvider {
  /** A valid access token, or throws AUTH_REQUIRED. */
  getToken(): Promise<string>;
  /** Called when the API rejected the token (401). */
  invalidate(token: string): Promise<void>;
}

/** Maps an HTTP error response to a transport error code. */
export function mapHttpError(status: number, body: string, retryAfter: string | null): RemoteError {
  const retryAfterMs = parseRetryAfter(retryAfter);
  if (status === 401) return new RemoteError("AUTH_REQUIRED");
  if (status === 429) return new RemoteError("RATE_LIMITED", retryAfterMs);
  if (status === 403) {
    const reason = errorReason(body);
    if (reason === "rateLimitExceeded" || reason === "userRateLimitExceeded" || reason === "dailyLimitExceeded") {
      return new RemoteError("RATE_LIMITED", retryAfterMs);
    }
    if (reason === "insufficientPermissions" || reason === "authError" || reason === "insufficientScopes") {
      return new RemoteError("AUTH_REQUIRED");
    }
    return new RemoteError("REMOTE_ERROR");
  }
  if (status === 408 || status === 500 || status === 502 || status === 503 || status === 504) {
    return new RemoteError("NETWORK", retryAfterMs);
  }
  return new RemoteError("REMOTE_ERROR");
}

function parseRetryAfter(v: string | null): number | undefined {
  if (!v) return undefined;
  const secs = Number(v);
  if (Number.isFinite(secs) && secs >= 0) return secs * 1000;
  const at = Date.parse(v);
  return Number.isFinite(at) ? Math.max(0, at - Date.now()) : undefined;
}

function errorReason(body: string): string | null {
  try {
    const j = JSON.parse(body) as { error?: { errors?: Array<{ reason?: unknown }>; status?: unknown } };
    const r = j.error?.errors?.[0]?.reason;
    if (typeof r === "string") return r;
    return j.error?.status === "PERMISSION_DENIED" ? "insufficientPermissions" : null;
  } catch {
    return null;
  }
}

function toMeta(j: unknown): RemoteMeta {
  const o = (j ?? {}) as Record<string, unknown>;
  const id = o["id"];
  const head = o["headRevisionId"];
  if (typeof id !== "string" || typeof head !== "string" || !id || !head) throw new RemoteError("REMOTE_ERROR");
  const size = Number(o["size"] ?? 0);
  return {
    fileId: id,
    headRevisionId: head,
    modifiedTime: typeof o["modifiedTime"] === "string" ? o["modifiedTime"] : "",
    size: Number.isFinite(size) ? size : 0,
  };
}

function randomBoundary(): string {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return `keyvora-${Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("")}`;
}

export interface GoogleDriveOptions {
  fetch: FetchLike;
  tokens: TokenProvider;
  boundary?: () => string;
  /** Tests only; default MAX_DOWNLOAD_BYTES. */
  maxDownloadBytes?: number;
}

export class GoogleDriveRemoteStore implements RemoteStore {
  readonly #fetch: FetchLike;
  readonly #tokens: TokenProvider;
  readonly #boundary: () => string;
  readonly #maxDownload: number;

  constructor(opts: GoogleDriveOptions) {
    this.#fetch = opts.fetch;
    this.#tokens = opts.tokens;
    this.#boundary = opts.boundary ?? randomBoundary;
    this.#maxDownload = opts.maxDownloadBytes ?? MAX_DOWNLOAD_BYTES;
  }

  async #request(url: string, init: { method?: string; headers?: Record<string, string>; body?: string } = {}): Promise<Response> {
    const token = await this.#tokens.getToken();
    let res: Response;
    try {
      res = await this.#fetch(url, {
        method: init.method ?? "GET",
        headers: { ...(init.headers ?? {}), Authorization: `Bearer ${token}` },
        ...(init.body !== undefined ? { body: init.body } : {}),
        cache: "no-store",
        credentials: "omit",
        referrerPolicy: "no-referrer",
      });
    } catch {
      throw new RemoteError("NETWORK");
    }
    if (!res.ok) {
      let body = "";
      try {
        body = await res.text();
      } catch {
        /* ignore */
      }
      const err = mapHttpError(res.status, body, res.headers.get("Retry-After"));
      if (err.code === "AUTH_REQUIRED") await this.#tokens.invalidate(token);
      throw err;
    }
    return res;
  }

  async #json(url: string, init?: { method?: string; headers?: Record<string, string>; body?: string }): Promise<unknown> {
    const res = await this.#request(url, init);
    try {
      return await res.json();
    } catch {
      throw new RemoteError("REMOTE_ERROR");
    }
  }

  /** Reads the body with a byte cap; an oversized file is REMOTE_ERROR (not retryable), a broken stream NETWORK. */
  async #text(url: string): Promise<string> {
    const res = await this.#request(url);
    const max = this.#maxDownload;
    const tooBig = () => new RemoteError("REMOTE_ERROR");
    if (Number(res.headers.get("content-length") ?? 0) > max) {
      await res.body?.cancel().catch(() => undefined);
      throw tooBig();
    }
    if (!res.body) return "";
    const reader = res.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > max) {
          await reader.cancel().catch(() => undefined);
          throw tooBig();
        }
        chunks.push(value);
      }
    } catch (e) {
      throw e instanceof RemoteError ? e : new RemoteError("NETWORK");
    }
    const all = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) {
      all.set(c, off);
      off += c.byteLength;
    }
    return new TextDecoder().decode(all);
  }

  async getMetadata(): Promise<RemoteMeta | null> {
    const q = new URLSearchParams({
      spaces: "appDataFolder",
      q: `name = '${VAULT_FILE_NAME}' and trashed = false`,
      fields: `files(${META_FIELDS})`,
      orderBy: "createdTime",
      pageSize: "10",
    });
    const j = (await this.#json(`${DRIVE_API}/files?${q}`)) as { files?: unknown };
    if (!Array.isArray(j.files)) throw new RemoteError("REMOTE_ERROR");
    // Oldest file first: if two clients ever created the file concurrently, every client picks the same one.
    return j.files.length === 0 ? null : toMeta(j.files[0]);
  }

  async download(fileId: string): Promise<{ content: string; headRevisionId: string }> {
    const meta = toMeta(await this.#json(`${DRIVE_API}/files/${encodeURIComponent(fileId)}?${new URLSearchParams({ fields: META_FIELDS })}`));
    // Download that exact revision so content and revision id always correspond.
    const content = await this.downloadRevision(fileId, meta.headRevisionId);
    return { content, headRevisionId: meta.headRevisionId };
  }

  async create(content: string): Promise<RemoteMeta> {
    let boundary = this.#boundary();
    while (content.includes(boundary)) boundary = this.#boundary();
    const metadata = JSON.stringify({ name: VAULT_FILE_NAME, parents: ["appDataFolder"], mimeType: "application/json" });
    const body =
      `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${metadata}\r\n` +
      `--${boundary}\r\nContent-Type: application/json\r\n\r\n${content}\r\n--${boundary}--`;
    const q = new URLSearchParams({ uploadType: "multipart", fields: META_FIELDS });
    return toMeta(
      await this.#json(`${DRIVE_UPLOAD_API}/files?${q}`, {
        method: "POST",
        headers: { "Content-Type": `multipart/related; boundary=${boundary}` },
        body,
      }),
    );
  }

  async update(fileId: string, content: string): Promise<RemoteMeta> {
    const q = new URLSearchParams({ uploadType: "media", fields: META_FIELDS });
    return toMeta(
      await this.#json(`${DRIVE_UPLOAD_API}/files/${encodeURIComponent(fileId)}?${q}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: content,
      }),
    );
  }

  async listRevisions(fileId: string): Promise<RevisionInfo[]> {
    const out: RevisionInfo[] = [];
    let pageToken: string | null = null;
    for (let page = 0; page < 50; page++) {
      const q = new URLSearchParams({ fields: "nextPageToken,revisions(id,modifiedTime,size)", pageSize: "200" });
      if (pageToken) q.set("pageToken", pageToken);
      const j = (await this.#json(`${DRIVE_API}/files/${encodeURIComponent(fileId)}/revisions?${q}`)) as {
        revisions?: unknown;
        nextPageToken?: unknown;
      };
      if (j.revisions !== undefined && !Array.isArray(j.revisions)) throw new RemoteError("REMOTE_ERROR");
      for (const r of (j.revisions as Array<Record<string, unknown>> | undefined) ?? []) {
        if (typeof r["id"] !== "string") throw new RemoteError("REMOTE_ERROR");
        const size = Number(r["size"] ?? 0);
        out.push({
          id: r["id"],
          modifiedTime: typeof r["modifiedTime"] === "string" ? r["modifiedTime"] : "",
          size: Number.isFinite(size) ? size : 0,
        });
      }
      pageToken = typeof j.nextPageToken === "string" && j.nextPageToken ? j.nextPageToken : null;
      if (!pageToken) break;
    }
    // Contract: chronological order. Drive already returns it; a stable sort guards against surprises.
    return out.map((r, i) => ({ r, i })).sort((a, b) => (a.r.modifiedTime < b.r.modifiedTime ? -1 : a.r.modifiedTime > b.r.modifiedTime ? 1 : a.i - b.i)).map((x) => x.r);
  }

  async downloadRevision(fileId: string, revisionId: string): Promise<string> {
    const url = `${DRIVE_API}/files/${encodeURIComponent(fileId)}/revisions/${encodeURIComponent(revisionId)}?alt=media`;
    return this.#text(url);
  }
}
