// Firefox E2E: the same checks as extension.spec.ts (Chromium), run against real Firefox.
// The extension is installed as a temporary add-on with Mozilla's web-ext (remote debugging protocol) and the pages
// are driven with puppeteer-core over WebDriver BiDi (no unsigned browser builds, so it also works under Windows
// Smart App Control). Fills go through the E2E test hook (__keyvoraTest) of the background page.
//
// Usage (after `npm run build:e2e`; web-ext and puppeteer-core are NOT project dependencies):
//   npm i --prefix <tools-dir> web-ext@8 puppeteer-core@24
//   KEYVORA_E2E_TOOLS=<tools-dir>/node_modules KEYVORA_FIREFOX="<path to firefox.exe>" node test/e2e/firefox-e2e.mjs
import { cpSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { fileURLToPath, pathToFileURL } from "node:url";
import assert from "node:assert/strict";
import { startFixtureServer } from "./server.ts";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
// node_modules folder holding web-ext and puppeteer-core (they are not project dependencies).
const TOOLS = process.env.KEYVORA_E2E_TOOLS ?? path.join(ROOT, "node_modules");
const webExt = (await import(pathToFileURL(path.join(TOOLS, "web-ext", "index.js")).href)).default;
const puppeteer = (await import(pathToFileURL(path.join(TOOLS, "puppeteer-core", "lib", "esm", "puppeteer", "puppeteer-core.js")).href)).default;
const FIREFOX = process.env.KEYVORA_FIREFOX;
assert.ok(FIREFOX, "KEYVORA_FIREFOX must point to firefox.exe");
assert.ok(existsSync(path.join(ROOT, "dist", "e2e", "background.js")), "run npm run build:e2e first");
const MASTER = "frase maestra de prueba e2e";
const PORT = 9300 + Math.floor(Math.random() * 500);

// Firefox flavour of the E2E build: Firefox manifest (background.scripts) + host permissions for the fixtures.
const ffManifest = JSON.parse(readFileSync(path.join(ROOT, "dist", "manifest.firefox.json"), "utf8"));
const GECKO_ID = ffManifest.browser_specific_settings.gecko.id;
const extDir = mkdtempSync(path.join(os.tmpdir(), "keyvora-ff-ext-"));
cpSync(path.join(ROOT, "dist", "e2e"), extDir, { recursive: true });
writeFileSync(path.join(extDir, "manifest.json"), JSON.stringify({ ...ffManifest, host_permissions: ["http://127.0.0.1/*", "http://localhost/*"] }, null, 2));

/** Polls `fn` in the page with plain evaluate() calls (puppeteer's waitForFunction injects code that the extension
 *  pages' strict CSP blocks in Firefox). */
async function waitFor(page, fn, timeout) {
  const end = Date.now() + timeout;
  for (;;) {
    if (await page.evaluate(fn).catch(() => false)) return;
    if (Date.now() > end) throw new Error(`timed out after ${timeout} ms`);
    await new Promise((r) => setTimeout(r, 250));
  }
}

const results = [];
async function check(name, fn) {
  try {
    await fn();
    results.push({ name, ok: true });
    console.log(`  ✔ ${name}`);
  } catch (e) {
    results.push({ name, ok: false, error: String(e?.message ?? e) });
    console.log(`  ✘ ${name}\n      ${String(e?.message ?? e).split("\n")[0]}`);
  }
}

/** Reads the moz-extension UUID Firefox assigned to the add-on from the temporary profile's prefs.js. */
async function assignedUuid(profilesBefore) {
  for (let i = 0; i < 60; i++) {
    const profiles = readdirSync(os.tmpdir())
      .filter((d) => d.startsWith("firefox-profile") && !profilesBefore.has(d))
      .sort((a, b) => statSync(path.join(os.tmpdir(), b)).mtimeMs - statSync(path.join(os.tmpdir(), a)).mtimeMs);
    for (const p of profiles) {
      try {
        const prefs = readFileSync(path.join(os.tmpdir(), p, "prefs.js"), "utf8");
        const m = prefs.match(/"extensions\.webextensions\.uuids", "(.*)"\);/);
        const map = m ? JSON.parse(m[1].replace(/\\"/g, '"')) : {};
        if (map[GECKO_ID]) return map[GECKO_ID];
      } catch {}
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error("could not find the add-on UUID in the temporary profile");
}

const server = await startFixtureServer();
const profilesBefore = new Set(readdirSync(os.tmpdir()).filter((d) => d.startsWith("firefox-profile")));
const runner = await webExt.cmd.run(
  {
    sourceDir: extDir,
    target: ["firefox-desktop"],
    firefox: FIREFOX,
    args: [`--remote-debugging-port=${PORT}`, "--headless"],
    noReload: true,
    noInput: true,
  },
  { shouldExitProgram: false },
);
let browser;
const UUID = await assignedUuid(profilesBefore);
try {
  browser = await puppeteer.connect({ browserWSEndpoint: `ws://127.0.0.1:${PORT}/session`, protocol: "webDriverBiDi" });
  const version = await browser.version();
  console.log(`Firefox: ${version}`);
  const popup = await browser.newPage();
  // Firefox 137's BiDi does not always report the load event for moz-extension pages: wait for the DOM instead.
  await popup.goto(`moz-extension://${UUID}/popup.html`, { waitUntil: "domcontentloaded", timeout: 10_000 }).catch(() => {});
  await popup.waitForSelector("#create-password", { timeout: 20_000 });

  // Helpers running in the (trusted) popup page: background page test hook and tab lookup.
  const hook = (type, payload, tabId) =>
    popup.evaluate(async (t, p, id) => (await browser.runtime.getBackgroundPage()).__keyvoraTest.handle(t, p, id ?? undefined), type, payload ?? null, tabId ?? null);
  const fill = (tabId, entryId, confirmed = false) =>
    popup.evaluate(async (id, e, c) => (await browser.runtime.getBackgroundPage()).__keyvoraTest.fill(id, e, c), tabId, entryId, confirmed);
  const tabIdOf = (url) => popup.evaluate(async (u) => (await browser.tabs.query({})).find((t) => t.url === u)?.id ?? -1, url);
  const addEntry = async (title, url, username = "alice", password = "pw-e2e-123") => {
    const r = await hook("createEntry", { input: { title, username, password, urls: [url], notes: "" } });
    assert.ok(r.ok, `createEntry: ${r.error}`);
    return r.data.id;
  };
  const value = (page, sel, frame = false) =>
    frame ? page.$eval("#frame", (f, s) => f.contentDocument?.querySelector(s)?.value ?? null, sel).catch(() => "<cross-origin>")
          : page.$eval(sel, (el) => el.value);

  let step = "";
  await check("crea la bóveda desde popup.html (WASM + Argon2id en la página de fondo)", async () => {
   try {
    step = "type passwords";
    await popup.type("#create-password", MASTER);
    await popup.type("#create-confirm", MASTER);
    const [btn] = await popup.$$("xpath/.//button[normalize-space()='Crear bóveda']");
    await btn.click();
    step = "wait recovery key";
    const t0 = Date.now();
    await waitFor(popup, () => /^[A-Z2-7]{4}(-[A-Z2-7]{4}){13}$/.test(document.querySelector("[data-testid=recovery-key]")?.textContent ?? ""), 300_000);
    console.log(`    (crear bóveda con Argon2id por defecto: ${((Date.now() - t0) / 1000).toFixed(1)} s)`);
    const key = await popup.$eval("[data-testid=recovery-key]", (el) => el.textContent);
    await popup.click("#rk-saved");
    await popup.type("#rk-last", key.split("-").at(-1).toLowerCase());
    const [cont] = await popup.$$("xpath/.//button[normalize-space()='Continuar']");
    await cont.click();
    step = "wait list heading";
    await waitFor(popup, () => [...document.querySelectorAll("h1,h2")].some((h) => h.textContent.trim() === "Keyvora"), 20_000);
    const st = await hook("status");
    assert.ok(st.ok && st.data.unlocked, "unlocked");
   } catch (e) {
    const dom = await popup.evaluate(() => document.body.innerText.replace(/\s+/g, " ").slice(0, 400)).catch((x) => String(x));
    throw new Error(`step "${step}": ${e.message.split(String.fromCharCode(10))[0]} | popup: ${dom}`);
   }
  });

  await check("rellena el formulario de login del origen exacto", async () => {
    const id = await addEntry("Local", server.base);
    const page = await browser.newPage();
    await page.goto(`${server.base}/login.html`);
    const r = await fill(await tabIdOf(page.url()), id);
    assert.deepEqual(r, { ok: true, data: { result: "filled" } });
    assert.equal(await value(page, "#username"), "alice");
    assert.equal(await value(page, "#password"), "pw-e2e-123");
    assert.equal(await value(page, "#honeypot"), "");
    await page.close();
  });

  await check("no rellena el iframe de otro origen", async () => {
    const list = await hook("list");
    const localId = list.data.find((e) => e.title === "Local").id;
    const crossId = await addEntry("Cross", server.cross, "mallory", "pw-cross");
    const page = await browser.newPage();
    await page.goto(`${server.base}/iframe.html`);
    await new Promise((r) => setTimeout(r, 500));
    const tabId = await tabIdOf(page.url());
    assert.deepEqual(await fill(tabId, localId), { ok: true, data: { result: "no-form" } });
    assert.deepEqual(await fill(tabId, crossId), { ok: false, error: "NO_MATCH" });
    const frame = page.frames().find((f) => f.url().startsWith(server.cross));
    assert.ok(frame, "cross-origin frame present");
    assert.equal(await frame.$eval("#password", (el) => el.value), "");
    await page.close();
  });

  await check("no rellena con una entrada de otro origen", async () => {
    const otherId = await addEntry("Otro", "https://example.com", "eve", "pw-other");
    const page = await browser.newPage();
    await page.goto(`${server.base}/login.html`);
    assert.deepEqual(await fill(await tabIdOf(page.url()), otherId), { ok: false, error: "NO_MATCH" });
    assert.equal(await value(page, "#password"), "");
    await page.close();
  });

  await check("genera, guarda y rellena un formulario de registro", async () => {
    const page = await browser.newPage();
    await page.goto(`${server.base}/register.html`);
    const r = await hook("generateAndFill", { title: "Registro", username: "bob@example.com", options: { length: 24 } }, await tabIdOf(page.url()));
    assert.ok(r.ok && r.data.result === "filled", JSON.stringify(r));
    const pw = await value(page, "#new-password");
    assert.equal(pw.length, 24);
    assert.equal(await value(page, "#confirm-password"), pw);
    await page.close();
  });

  await check("ignora los mensajes enviados por páginas web", async () => {
    const page = await browser.newPage();
    await page.goto(`${server.base}/message.html?ext=${encodeURIComponent(GECKO_ID)}`);
    await waitFor(page, () => document.body.dataset.result, 10_000);
    const result = await page.$eval("body", (b) => b.dataset.result);
    assert.ok(!result.includes("reply:{"), result);
    const st = await hook("status");
    assert.ok(st.ok && st.data.unlocked, "still unlocked");
    await page.close();
  });

  await check("tras bloquear, rellenar falla con LOCKED y storage.session queda vacío", async () => {
    const list = await hook("list");
    const id = list.data.find((e) => e.title === "Local").id;
    assert.ok((await hook("lock")).ok);
    const page = await browser.newPage();
    await page.goto(`${server.base}/login.html`);
    assert.deepEqual(await fill(await tabIdOf(page.url()), id), { ok: false, error: "LOCKED" });
    assert.equal(await value(page, "#password"), "");
    const keys = await popup.evaluate(async () => Object.keys(await browser.storage.session.get(null)));
    assert.deepEqual(keys, []);
    await page.close();
  });
  await check("identity.launchWebAuthFlow devuelve el token (flujo OAuth implícito, sin contactar con Google)", async () => {
    // Fake OAuth endpoint: redirects to the extension's redirect URL with a fake implicit-flow token.
    const auth = http.createServer((req, res) => {
      const u = new URL(req.url, "http://127.0.0.1");
      res.writeHead(302, { Location: `${u.searchParams.get("redirect_uri")}#access_token=fake-token-123&state=${u.searchParams.get("state")}` }).end();
    });
    await new Promise((r) => auth.listen(0, "127.0.0.1", r));
    try {
      const out = await popup.evaluate(async (port) => {
        const redirect = browser.identity.getRedirectURL();
        const final = await browser.identity.launchWebAuthFlow({ url: `http://127.0.0.1:${port}/auth?redirect_uri=${encodeURIComponent(redirect)}&state=xyz`, interactive: false });
        const h = new URLSearchParams(new URL(final).hash.slice(1));
        return { redirect, token: h.get("access_token"), state: h.get("state") };
      }, auth.address().port);
      assert.equal(out.token, "fake-token-123");
      assert.equal(out.state, "xyz");
      console.log(`    (redirect URI de Firefox: ${out.redirect})`);
    } finally {
      auth.close();
    }
  });
} finally {
  await browser?.disconnect().catch(() => {});
  runner.exit();
  await server.close();
  rmSync(extDir, { recursive: true, force: true });
}
const failed = results.filter((r) => !r.ok).length;
console.log(`\n${results.length - failed}/${results.length} passed`);
process.exit(failed ? 1 : 0);
