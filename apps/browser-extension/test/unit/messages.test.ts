import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { dispatch, type Handler } from "../../src/background/handlers.ts";
import { KvError, toErrorCode } from "../../src/shared/errors.ts";
import { isTrustedSender, MESSAGE_TYPES, parseEnvelope, type MessageType } from "../../src/shared/messages.ts";
import { entryInput, generatorOptions } from "../../src/shared/validate.ts";

const ID = "abcdefghijklmnopabcdefghijklmnop";
const POPUP = `chrome-extension://${ID}/popup.html`;

describe("parseEnvelope", () => {
  test("accepts a well-formed v1 message", () => {
    assert.deepEqual(parseEnvelope({ v: 1, type: "list" }), { v: 1, type: "list", payload: undefined });
    assert.deepEqual(parseEnvelope({ v: 1, type: "get", payload: { id: "x" } }), { v: 1, type: "get", payload: { id: "x" } });
  });
  test("rejects wrong version, unknown type, extra keys and non-objects", () => {
    for (const m of [null, undefined, "list", 42, [], { type: "list" }, { v: 2, type: "list" }, { v: 1, type: "evil" },
      { v: 1, type: "list", extra: true }, { v: "1", type: "list" }, { v: 1, type: "__proto__" }]) {
      assert.equal(parseEnvelope(m), null, JSON.stringify(m));
    }
  });
  test("covers exactly the contract types (CONTRACTS.md §5)", () => {
    assert.equal(MESSAGE_TYPES.length, 29);
    for (const t of ["status", "fill", "generateAndFill", "sync.connect", "sync.disconnect", "settings.set", "import", "export", "rotateDataKey", "sync.adoptRemoteKeys"]) {
      assert.ok((MESSAGE_TYPES as readonly string[]).includes(t), t);
    }
  });
});

describe("isTrustedSender", () => {
  test("accepts only the extension popup", () => {
    assert.equal(isTrustedSender({ id: ID, url: POPUP }, ID, POPUP), true);
    assert.equal(isTrustedSender({ id: ID, url: `${POPUP}?x=1#y`, origin: `chrome-extension://${ID}` }, ID, POPUP), true);
  });
  test("rejects other extensions, pages, content scripts and other extension pages", () => {
    const cases = [
      undefined,
      {},
      { id: ID },
      { id: "otherextensionidotherextensionid", url: POPUP },
      { id: ID, url: "https://evil.example/popup.html" },
      { id: ID, url: `chrome-extension://${ID}/options.html` },
      { id: ID, url: `chrome-extension://otherextensionidotherextensionid/popup.html` },
      { id: ID, url: "https://bank.example/login", origin: "https://bank.example" }, // content script in a page
      { id: ID, url: POPUP, origin: "https://evil.example" },
      { id: ID, url: "not a url" },
    ];
    for (const s of cases) assert.equal(isTrustedSender(s, ID, POPUP), false, JSON.stringify(s));
  });
  test("rejects when the runtime id is unknown", () => {
    assert.equal(isTrustedSender({ id: "", url: POPUP }, "", POPUP), false);
  });
});

describe("dispatch", () => {
  const handlers = Object.fromEntries(MESSAGE_TYPES.map((t) => [t, async () => ({ type: t })])) as unknown as Record<MessageType, Handler>;
  test("routes valid messages and wraps data", async () => {
    assert.deepEqual(await dispatch(handlers, { v: 1, type: "list" }), { ok: true, data: { type: "list" } });
  });
  test("invalid envelope → BAD_REQUEST", async () => {
    assert.deepEqual(await dispatch(handlers, { v: 1, type: "nope" }), { ok: false, error: "BAD_REQUEST" });
  });
  test("maps errors to stable codes without leaking messages", async () => {
    const h = { ...handlers };
    h.get = async () => {
      throw new Error("LOCKED");
    };
    h.list = async () => {
      throw new KvError("NO_MATCH");
    };
    h.search = async () => {
      throw new Error("hunter2 is the password of alice@example.com");
    };
    assert.deepEqual(await dispatch(h, { v: 1, type: "get" }), { ok: false, error: "LOCKED" });
    assert.deepEqual(await dispatch(h, { v: 1, type: "list" }), { ok: false, error: "NO_MATCH" });
    const r = await dispatch(h, { v: 1, type: "search" });
    assert.deepEqual(r, { ok: false, error: "UNKNOWN" });
    assert.ok(!JSON.stringify(r).includes("hunter2"));
  });
  test("toErrorCode", () => {
    assert.equal(toErrorCode(new Error("INVALID_CREDENTIALS")), "INVALID_CREDENTIALS");
    assert.equal(toErrorCode({ code: "NETWORK" }), "NETWORK");
    assert.equal(toErrorCode("boom"), "UNKNOWN");
  });
});

describe("payload validators", () => {
  test("entryInput normalizes and rejects bad shapes", () => {
    assert.deepEqual(entryInput({ title: "A", urls: [" https://a.example ", ""] }), { title: "A", username: "", password: "", urls: ["https://a.example"], notes: "" });
    assert.throws(() => entryInput({ title: 1, urls: [] }), /BAD_REQUEST/);
    assert.throws(() => entryInput({ title: "A", urls: "https://a" }), /BAD_REQUEST/);
    assert.throws(() => entryInput({ title: "A", urls: Array(17).fill("https://a.example") }), /BAD_REQUEST/);
  });
  test("generatorOptions enforces 8–128 and known keys", () => {
    assert.deepEqual(generatorOptions({ length: 32, symbols: false }), { length: 32, symbols: false });
    assert.throws(() => generatorOptions({ length: 7 }), /BAD_REQUEST/);
    assert.throws(() => generatorOptions({ length: 129 }), /BAD_REQUEST/);
    assert.throws(() => generatorOptions({ length: 20.5 }), /BAD_REQUEST/);
    assert.throws(() => generatorOptions({ evil: true }), /BAD_REQUEST/);
    assert.throws(() => generatorOptions({ digits: "yes" }), /BAD_REQUEST/);
  });
});
