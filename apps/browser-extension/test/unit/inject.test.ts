// Unit tests of the injected fill functions against a minimal fake DOM (the E2E suite covers real Chromium).
import assert from "node:assert/strict";
import { afterEach, describe, test } from "node:test";
import { fillLoginInPage, fillNewPasswordInPage, type FillArgs } from "../../src/background/inject.ts";

interface Opts {
  type?: string;
  form?: object | null;
  visible?: boolean;
  disabled?: boolean;
  readOnly?: boolean;
  offscreen?: boolean;
  opacity?: string;
  value?: string;
}

class FakeInput extends EventTarget {
  type: string;
  form: object | null;
  disabled: boolean;
  readOnly: boolean;
  events: string[] = [];
  _value: string;
  style: { visibility: string; display: string; opacity: string };
  rect: { width: number; height: number; right: number; bottom: number };
  constructor(o: Opts) {
    super();
    this.type = o.type ?? "text";
    this.form = o.form === undefined ? null : o.form;
    this.disabled = o.disabled ?? false;
    this.readOnly = o.readOnly ?? false;
    this._value = o.value ?? "";
    const visible = o.visible ?? true;
    this.style = { visibility: "visible", display: visible ? "inline-block" : "none", opacity: o.opacity ?? "1" };
    this.rect = visible ? (o.offscreen ? { width: 100, height: 20, right: -9000, bottom: 20 } : { width: 100, height: 20, right: 120, bottom: 40 }) : { width: 0, height: 0, right: 0, bottom: 0 };
    this.addEventListener("input", () => this.events.push("input"));
    this.addEventListener("change", () => this.events.push("change"));
  }
  getBoundingClientRect() {
    return this.rect;
  }
  get value(): string {
    return this._value;
  }
  set value(v: string) {
    this._value = v;
  }
}

const g = globalThis as Record<string, unknown>;
const saved = ["location", "window", "document", "HTMLInputElement"].map((k) => [k, g[k]] as const);

function page(origin: string, inputs: FakeInput[], opts: { top?: boolean } = {}) {
  const win: Record<string, unknown> = { scrollX: 0, scrollY: 0, getComputedStyle: (el: FakeInput) => el.style };
  win["top"] = opts.top === false ? {} : win;
  g["window"] = win;
  g["location"] = { origin };
  g["document"] = { querySelectorAll: (sel: string) => (sel === "input" ? inputs : []) };
  g["HTMLInputElement"] = FakeInput;
}

afterEach(() => {
  for (const [k, v] of saved) {
    if (v === undefined) delete g[k];
    else g[k] = v;
  }
});

const ARGS: FillArgs = { expectedOrigin: "https://example.com", username: "alice", password: "s3cret" };

describe("fillLoginInPage", () => {
  test("fills username (nearest preceding text field in the same form) and password, dispatching events", () => {
    const form = {};
    const search = new FakeInput({ type: "search" });
    const other = new FakeInput({ type: "email", form: {} });
    const user = new FakeInput({ type: "email", form });
    const pw = new FakeInput({ type: "password", form });
    page("https://example.com", [search, other, user, pw]);
    assert.equal(fillLoginInPage(ARGS), "filled");
    assert.equal(user.value, "alice");
    assert.equal(pw.value, "s3cret");
    assert.equal(other.value, "", "field of another form untouched");
    assert.deepEqual(pw.events, ["input", "change"]);
    assert.deepEqual(user.events, ["input", "change"]);
  });

  test("aborts on origin mismatch or when not in the top frame", () => {
    const pw = new FakeInput({ type: "password" });
    page("https://evil.example", [pw]);
    assert.equal(fillLoginInPage(ARGS), "origin-mismatch");
    page("https://example.com", [pw], { top: false });
    assert.equal(fillLoginInPage(ARGS), "origin-mismatch");
    assert.equal(pw.value, "");
  });

  test("no visible password field → no-form (hidden, disabled, read-only, off-screen, transparent are ignored)", () => {
    const fields = [
      new FakeInput({ type: "password", visible: false }),
      new FakeInput({ type: "password", disabled: true }),
      new FakeInput({ type: "password", readOnly: true }),
      new FakeInput({ type: "password", offscreen: true }),
      new FakeInput({ type: "password", opacity: "0" }),
    ];
    page("https://example.com", fields);
    assert.equal(fillLoginInPage(ARGS), "no-form");
    assert.ok(fields.every((f) => f.value === ""));
  });

  test("more than one visible password field → ambiguous, nothing filled", () => {
    const a = new FakeInput({ type: "password" });
    const b = new FakeInput({ type: "password" });
    page("https://example.com", [a, b]);
    assert.equal(fillLoginInPage(ARGS), "ambiguous");
    assert.equal(a.value + b.value, "");
  });

  test("hidden honeypot username fields are skipped", () => {
    const form = {};
    const user = new FakeInput({ type: "text", form });
    const honeypot = new FakeInput({ type: "text", form, visible: false });
    const pw = new FakeInput({ type: "password", form });
    page("https://example.com", [user, honeypot, pw]);
    assert.equal(fillLoginInPage(ARGS), "filled");
    assert.equal(user.value, "alice");
    assert.equal(honeypot.value, "");
  });

  test("is self-contained (no references outside its body)", () => {
    const src = fillLoginInPage.toString();
    assert.doesNotMatch(src, /\bimport\b|\brequire\(/);
  });
});

describe("fillNewPasswordInPage", () => {
  test("fills new + confirmation fields of one form", () => {
    const form = {};
    const user = new FakeInput({ type: "email", form });
    const p1 = new FakeInput({ type: "password", form });
    const p2 = new FakeInput({ type: "password", form });
    page("https://example.com", [user, p1, p2]);
    assert.equal(fillNewPasswordInPage(ARGS), "filled");
    assert.equal(p1.value, "s3cret");
    assert.equal(p2.value, "s3cret");
    assert.equal(user.value, "alice");
  });

  test("three password fields or several forms → ambiguous", () => {
    const form = {};
    page("https://example.com", [new FakeInput({ type: "password", form }), new FakeInput({ type: "password", form }), new FakeInput({ type: "password", form })]);
    assert.equal(fillNewPasswordInPage(ARGS), "ambiguous");
    page("https://example.com", [new FakeInput({ type: "password", form: {} }), new FakeInput({ type: "password", form: {} })]);
    assert.equal(fillNewPasswordInPage(ARGS), "ambiguous");
  });

  test("origin mismatch aborts", () => {
    page("https://example.com.evil.example", [new FakeInput({ type: "password" })]);
    assert.equal(fillNewPasswordInPage(ARGS), "origin-mismatch");
  });
});
