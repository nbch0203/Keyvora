import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { DRIVE_API, DRIVE_UPLOAD_API, GoogleDriveRemoteStore, mapHttpError, META_FIELDS, VAULT_FILE_NAME } from "../../src/sync/google-drive.ts";
import { RemoteError } from "../../src/sync/types.ts";

interface Captured {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string | undefined;
}

const TOKEN = "ya29.test-token-value";

function mockFetch(responses: Array<Response | (() => Response) | Error>) {
  const calls: Captured[] = [];
  const fetch = async (url: string, init?: RequestInit): Promise<Response> => {
    calls.push({ url, method: init?.method ?? "GET", headers: { ...(init?.headers as Record<string, string>) }, body: init?.body as string | undefined });
    const next = responses.shift();
    if (!next) throw new Error("unexpected request");
    if (next instanceof Error) throw next;
    return typeof next === "function" ? next() : next;
  };
  return { fetch, calls };
}

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
}

function store(responses: Array<Response | (() => Response) | Error>) {
  const m = mockFetch(responses);
  const invalidated: string[] = [];
  const s = new GoogleDriveRemoteStore({
    fetch: m.fetch,
    tokens: { getToken: async () => TOKEN, invalidate: async (t) => void invalidated.push(t) },
    boundary: () => "BOUNDARY123",
  });
  return { s, calls: m.calls, invalidated };
}

describe("GoogleDriveRemoteStore requests", () => {
  test("getMetadata searches appDataFolder by name with minimal fields", async () => {
    const { s, calls } = store([json({ files: [{ id: "f1", headRevisionId: "r9", modifiedTime: "2026-11-15T10:00:00.000Z", size: "1234" }] })]);
    assert.deepEqual(await s.getMetadata(), { fileId: "f1", headRevisionId: "r9", modifiedTime: "2026-11-15T10:00:00.000Z", size: 1234 });
    const u = new URL(calls[0]!.url);
    assert.equal(`${u.origin}${u.pathname}`, `${DRIVE_API}/files`);
    assert.equal(u.searchParams.get("spaces"), "appDataFolder");
    assert.equal(u.searchParams.get("q"), `name = '${VAULT_FILE_NAME}' and trashed = false`);
    assert.equal(u.searchParams.get("fields"), `files(${META_FIELDS})`);
    assert.equal(META_FIELDS, "id,headRevisionId,modifiedTime,size");
    assert.equal(calls[0]!.method, "GET");
    assert.equal(calls[0]!.headers["Authorization"], `Bearer ${TOKEN}`);
  });

  test("getMetadata returns null when there is no file", async () => {
    const { s } = store([json({ files: [] })]);
    assert.equal(await s.getMetadata(), null);
  });

  test("download reads the head revision id and downloads exactly that revision", async () => {
    const { s, calls } = store([json({ id: "f1", headRevisionId: "r9", modifiedTime: "t", size: "3" }), new Response("{}")]);
    assert.deepEqual(await s.download("f1"), { content: "{}", headRevisionId: "r9" });
    assert.equal(new URL(calls[0]!.url).searchParams.get("fields"), META_FIELDS);
    assert.equal(calls[1]!.url, `${DRIVE_API}/files/f1/revisions/r9?alt=media`);
  });

  test("create uploads multipart into appDataFolder", async () => {
    const { s, calls } = store([json({ id: "f1", headRevisionId: "r1", modifiedTime: "t", size: "2" })]);
    const meta = await s.create('{"format":"keyvora.vault"}');
    assert.equal(meta.fileId, "f1");
    const c = calls[0]!;
    const u = new URL(c.url);
    assert.equal(c.method, "POST");
    assert.equal(`${u.origin}${u.pathname}`, `${DRIVE_UPLOAD_API}/files`);
    assert.equal(u.searchParams.get("uploadType"), "multipart");
    assert.equal(u.searchParams.get("fields"), META_FIELDS);
    assert.equal(c.headers["Content-Type"], "multipart/related; boundary=BOUNDARY123");
    const parts = c.body!.split("--BOUNDARY123");
    const metadata = JSON.parse(parts[1]!.split("\r\n\r\n")[1]!.trim());
    assert.deepEqual(metadata, { name: VAULT_FILE_NAME, parents: ["appDataFolder"], mimeType: "application/json" });
    assert.ok(parts[2]!.includes('{"format":"keyvora.vault"}'));
    assert.ok(c.body!.endsWith("--BOUNDARY123--"));
  });

  test("update uses PATCH on the upload endpoint with uploadType=media", async () => {
    const { s, calls } = store([json({ id: "f1", headRevisionId: "r2", modifiedTime: "t", size: "2" })]);
    const meta = await s.update("f1", "CONTENT");
    assert.equal(meta.headRevisionId, "r2");
    assert.equal(calls[0]!.method, "PATCH");
    assert.equal(calls[0]!.url, `https://www.googleapis.com/upload/drive/v3/files/f1?uploadType=media&fields=${encodeURIComponent(META_FIELDS)}`);
    assert.equal(calls[0]!.body, "CONTENT");
    assert.equal(calls[0]!.headers["Content-Type"], "application/json");
  });

  test("listRevisions follows pagination and returns chronological order", async () => {
    const { s, calls } = store([
      json({ revisions: [{ id: "r1", modifiedTime: "2026-01-01T00:00:00.000Z", size: "1" }, { id: "r2", modifiedTime: "2026-01-02T00:00:00.000Z", size: "2" }], nextPageToken: "P2" }),
      json({ revisions: [{ id: "r3", modifiedTime: "2026-01-03T00:00:00.000Z", size: "3" }] }),
    ]);
    const revs = await s.listRevisions("f1");
    assert.deepEqual(revs.map((r) => r.id), ["r1", "r2", "r3"]);
    assert.equal(revs[2]!.size, 3);
    assert.equal(new URL(calls[0]!.url).pathname, "/drive/v3/files/f1/revisions");
    assert.equal(new URL(calls[1]!.url).searchParams.get("pageToken"), "P2");
  });

  test("downloadRevision uses alt=media", async () => {
    const { s, calls } = store([new Response("OLD")]);
    assert.equal(await s.downloadRevision("f1", "r1"), "OLD");
    assert.equal(calls[0]!.url, `${DRIVE_API}/files/f1/revisions/r1?alt=media`);
  });

  test("ids are URL-encoded", async () => {
    const { s, calls } = store([new Response("X")]);
    await s.downloadRevision("f/1?x", "r#1");
    assert.equal(calls[0]!.url, `${DRIVE_API}/files/f%2F1%3Fx/revisions/r%231?alt=media`);
  });
});

describe("GoogleDriveRemoteStore error mapping", () => {
  const err = (status: number, body: unknown = {}, headers: Record<string, string> = {}) => json(body, status, headers);
  const reason = (r: string) => ({ error: { errors: [{ reason: r }], code: 403 } });

  async function codeOf(p: Promise<unknown>): Promise<RemoteError> {
    try {
      await p;
    } catch (e) {
      assert.ok(e instanceof RemoteError, "RemoteError expected");
      return e;
    }
    assert.fail("expected rejection");
  }

  test("401 → AUTH_REQUIRED and the token is invalidated", async () => {
    const { s, invalidated } = store([err(401)]);
    assert.equal((await codeOf(s.getMetadata())).code, "AUTH_REQUIRED");
    assert.deepEqual(invalidated, [TOKEN]);
  });
  test("403 rate limit reasons → RATE_LIMITED", async () => {
    for (const r of ["rateLimitExceeded", "userRateLimitExceeded"]) {
      const { s } = store([err(403, reason(r))]);
      assert.equal((await codeOf(s.getMetadata())).code, "RATE_LIMITED");
    }
  });
  test("403 insufficientPermissions → AUTH_REQUIRED; other 403 → REMOTE_ERROR", async () => {
    assert.equal((await codeOf(store([err(403, reason("insufficientPermissions"))]).s.getMetadata())).code, "AUTH_REQUIRED");
    assert.equal((await codeOf(store([err(403, reason("storageQuotaExceeded"))]).s.getMetadata())).code, "REMOTE_ERROR");
  });
  test("429 → RATE_LIMITED with Retry-After", async () => {
    const e = await codeOf(store([err(429, {}, { "Retry-After": "7" })]).s.getMetadata());
    assert.equal(e.code, "RATE_LIMITED");
    assert.equal(e.retryAfterMs, 7000);
  });
  test("5xx and 408 → NETWORK (retryable)", async () => {
    for (const st of [500, 502, 503, 504, 408]) assert.equal((await codeOf(store([err(st)]).s.getMetadata())).code, "NETWORK", String(st));
  });
  test("404 and other 4xx → REMOTE_ERROR", async () => {
    for (const st of [400, 404, 409]) assert.equal((await codeOf(store([err(st)]).s.download("f1"))).code, "REMOTE_ERROR", String(st));
  });
  test("fetch failure → NETWORK", async () => {
    assert.equal((await codeOf(store([new TypeError("Failed to fetch")]).s.getMetadata())).code, "NETWORK");
  });
  test("malformed success bodies → REMOTE_ERROR", async () => {
    assert.equal((await codeOf(store([new Response("not json", { status: 200 })]).s.getMetadata())).code, "REMOTE_ERROR");
    assert.equal((await codeOf(store([json({ files: [{ id: "f1" }] })]).s.getMetadata())).code, "REMOTE_ERROR");
  });
  test("missing token propagates AUTH_REQUIRED without any request", async () => {
    let requests = 0;
    const s = new GoogleDriveRemoteStore({
      fetch: async () => {
        requests++;
        return json({});
      },
      tokens: { getToken: async () => Promise.reject(new RemoteError("AUTH_REQUIRED")), invalidate: async () => undefined },
    });
    assert.equal((await codeOf(s.getMetadata())).code, "AUTH_REQUIRED");
    assert.equal(requests, 0);
  });
  test("errors never carry the token or the response body", async () => {
    const e = await codeOf(store([err(500, { secret: "BODY-SECRET" })]).s.getMetadata());
    assert.ok(!`${e.message}${e.stack}`.includes(TOKEN));
    assert.ok(!`${e.message}${e.stack}`.includes("BODY-SECRET"));
  });
  test("mapHttpError parses Retry-After as HTTP date", () => {
    const e = mapHttpError(429, "", new Date(Date.now() + 10_000).toUTCString());
    assert.ok(e.retryAfterMs! > 5_000 && e.retryAfterMs! <= 10_000);
  });
});
