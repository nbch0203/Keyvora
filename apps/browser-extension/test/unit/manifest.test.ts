import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { describe, test } from "node:test";
import { assertBaseManifest, chromiumManifest, E2E_HOSTS, e2eManifest, firefoxManifest, FORBIDDEN_KEYS } from "../../scripts/manifest.mjs";
import { EXT_ROOT } from "./helpers/core.ts";

const base = JSON.parse(readFileSync(path.join(EXT_ROOT, "manifest.json"), "utf8"));
const PERMS = ["storage", "alarms", "activeTab", "scripting", "identity"];

describe("manifest (ADR-009)", () => {
  test("permissions are exactly the five allowed ones", () => {
    assert.deepEqual([...base.permissions].sort(), [...PERMS].sort());
    assertBaseManifest(base);
  });
  test("no host permissions, content scripts, externally_connectable or web_accessible_resources", () => {
    for (const k of FORBIDDEN_KEYS as string[]) assert.equal(k in base, false, k);
    for (const m of [chromiumManifest(base), firefoxManifest(base)]) {
      for (const k of FORBIDDEN_KEYS as string[]) assert.equal(k in m, false, k);
      assert.deepEqual([...m.permissions].sort(), [...PERMS].sort());
    }
  });
  test("strict CSP with wasm-unsafe-eval only", () => {
    assert.equal(base.content_security_policy.extension_pages, "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'");
  });
  test("module service worker and action popup", () => {
    assert.deepEqual(base.background, { service_worker: "background.js", type: "module" });
    assert.equal(base.action.default_popup, "popup.html");
  });
  test("Firefox variant uses background.scripts and browser_specific_settings", () => {
    const f = firefoxManifest(base);
    assert.deepEqual(f.background, { scripts: ["background.js"], type: "module" });
    assert.ok(f.browser_specific_settings.gecko.id);
    assert.equal("minimum_chrome_version" in f, false);
  });
  test("E2E variant only adds local host permissions", () => {
    const e = e2eManifest(base);
    assert.deepEqual(e.host_permissions, E2E_HOSTS);
    assert.deepEqual([...e.permissions].sort(), [...PERMS].sort());
  });
  test("a drifted manifest is rejected by the build", () => {
    assert.throws(() => assertBaseManifest({ ...base, permissions: [...PERMS, "tabs"] }));
    assert.throws(() => assertBaseManifest({ ...base, host_permissions: ["<all_urls>"] }));
    assert.throws(() => assertBaseManifest({ ...base, content_scripts: [] }));
  });
});

describe("no secret logging (THREAT_MODEL T13)", () => {
  function walk(dir: string): string[] {
    return readdirSync(dir).flatMap((n) => {
      const p = path.join(dir, n);
      if (n === "pkg") return [];
      return statSync(p).isDirectory() ? walk(p) : p.endsWith(".ts") ? [p] : [];
    });
  }
  test("src/ contains no console.* calls and no onMessageExternal listener", () => {
    for (const f of walk(path.join(EXT_ROOT, "src"))) {
      const code = readFileSync(f, "utf8");
      assert.doesNotMatch(code, /\bconsole\.(log|info|debug|warn|error|trace)\s*\(/, f);
      assert.doesNotMatch(code, /onMessageExternal|onConnectExternal/, f);
      assert.doesNotMatch(code, /\binnerHTML\b|\bouterHTML\b|insertAdjacentHTML/, f);
    }
  });
});
