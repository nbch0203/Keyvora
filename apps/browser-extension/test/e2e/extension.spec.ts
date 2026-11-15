// E2E: Chromium with dist/e2e loaded. The vault is created through popup.html; fills are triggered through the
// test hook (__keyvoraTest, present only in E2E builds) because Playwright cannot click the toolbar action.
import { chromium, expect, test, type BrowserContext, type Page, type Worker } from "@playwright/test";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { startFixtureServer, type FixtureServer } from "./server.ts";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const EXT = path.join(ROOT, "dist", "e2e");
const HAS_PKG = existsSync(path.join(ROOT, "src", "core", "pkg", "keyvora_wasm_bg.wasm"));
const MASTER = "frase maestra de prueba e2e";
// Playwright's bundled Chromium by default; KEYVORA_E2E_CHANNEL=msedge uses the installed (signed) Edge instead,
// e.g. on Windows with Smart App Control, which blocks the unsigned Playwright build.
// KEYVORA_E2E_EXECUTABLE=<path to chrome/msedge.exe> overrides both.
const CHANNEL = process.env["KEYVORA_E2E_CHANNEL"] || "chromium";
const EXECUTABLE = process.env["KEYVORA_E2E_EXECUTABLE"] || undefined;

type Reply<T = unknown> = { ok: true; data: T } | { ok: false; error: string };

test.skip(!HAS_PKG, "núcleo WASM ausente (src/core/pkg): ejecuta scripts/wsl/build-wasm.sh y npm run build:e2e");
test.describe.configure({ mode: "serial" });

let server: FixtureServer;
let context: BrowserContext;
let sw: Worker;
let extId: string;
let userDataDir: string;

async function hook<T = unknown>(type: string, payload?: unknown, tabId?: number): Promise<Reply<T>> {
  return sw.evaluate(
    ([t, p, id]) => (globalThis as unknown as { __keyvoraTest: { handle(t: string, p: unknown, id?: number): Promise<unknown> } }).__keyvoraTest.handle(t, p, id ?? undefined),
    [type, payload ?? null, tabId ?? null] as const,
  ) as Promise<Reply<T>>;
}

async function fill(tabId: number, entryId: string, confirmed = false): Promise<Reply<{ result: string }>> {
  return sw.evaluate(
    ([id, e, c]) => (globalThis as unknown as { __keyvoraTest: { fill(t: number, e: string, c: boolean): Promise<unknown> } }).__keyvoraTest.fill(id, e, c),
    [tabId, entryId, confirmed] as const,
  ) as Promise<Reply<{ result: string }>>;
}

async function tabIdOf(page: Page): Promise<number> {
  const url = page.url();
  const id = await sw.evaluate(async (u) => {
    const tabs = await chrome.tabs.query({});
    return tabs.find((t) => t.url === u)?.id ?? -1;
  }, url);
  expect(id).toBeGreaterThan(-1);
  return id;
}

async function addEntry(title: string, url: string, username = "alice", password = "pw-e2e-123"): Promise<string> {
  const r = await hook<{ id: string }>("createEntry", { input: { title, username, password, urls: [url], notes: "" } });
  if (!r.ok) throw new Error(`createEntry failed: ${r.error}`);
  return r.data.id;
}

test.beforeAll(async () => {
  test.skip(!existsSync(path.join(EXT, "manifest.json")), "dist/e2e no existe: ejecuta npm run build:e2e");
  server = await startFixtureServer();
  userDataDir = mkdtempSync(path.join(os.tmpdir(), "keyvora-e2e-"));
  context = await chromium.launchPersistentContext(userDataDir, {
    ...(EXECUTABLE ? { executablePath: EXECUTABLE } : { channel: CHANNEL }),
    args: [`--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`],
  });
  sw = context.serviceWorkers()[0] ?? (await context.waitForEvent("serviceworker"));
  extId = new URL(sw.url()).host;
});

test.afterAll(async () => {
  await context?.close();
  await server?.close();
  if (userDataDir) rmSync(userDataDir, { recursive: true, force: true });
});

test("crea la bóveda desde popup.html", async () => {
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extId}/popup.html`);
  await page.locator("#create-password").fill(MASTER);
  await page.locator("#create-confirm").fill(MASTER);
  await page.getByRole("button", { name: "Crear bóveda" }).click();
  const keyBox = page.getByTestId("recovery-key");
  await expect(keyBox).toHaveText(/^[A-Z2-7]{4}(-[A-Z2-7]{4}){13}$/, { timeout: 30_000 });
  const key = (await keyBox.textContent()) ?? "";
  const continueBtn = page.getByRole("button", { name: "Continuar" });
  await expect(continueBtn).toBeDisabled();
  await page.locator("#rk-saved").check();
  await page.locator("#rk-last").fill(key.split("-").at(-1)!.toLowerCase());
  await expect(continueBtn).toBeEnabled();
  await continueBtn.click();
  await expect(page.getByRole("heading", { name: "Keyvora" })).toBeVisible();
  const st = await hook<{ unlocked: boolean }>("status");
  expect(st.ok && st.data.unlocked).toBe(true);
  await page.close();
});

test("rellena el formulario de login del origen exacto", async () => {
  const id = await addEntry("Local", server.base);
  const page = await context.newPage();
  await page.goto(`${server.base}/login.html`);
  const r = await fill(await tabIdOf(page), id);
  expect(r).toEqual({ ok: true, data: { result: "filled" } });
  await expect(page.locator("#username")).toHaveValue("alice");
  await expect(page.locator("#password")).toHaveValue("pw-e2e-123");
  await expect(page.locator("#honeypot")).toHaveValue("");
  await expect(page.locator("#search")).toHaveValue("");
  await page.close();
});

test("no rellena el iframe de otro origen", async () => {
  const topId = (await hook<Array<{ id: string; title: string }>>("list")) as { ok: true; data: Array<{ id: string; title: string }> };
  const localId = topId.data.find((e) => e.title === "Local")!.id;
  const crossId = await addEntry("Cross", server.cross, "mallory", "pw-cross");
  const page = await context.newPage();
  await page.goto(`${server.base}/iframe.html`);
  const frame = page.frameLocator("#frame");
  await expect(frame.locator("#password")).toBeVisible();
  const tabId = await tabIdOf(page);
  expect(await fill(tabId, localId)).toEqual({ ok: true, data: { result: "no-form" } });
  expect(await fill(tabId, crossId)).toEqual({ ok: false, error: "NO_MATCH" });
  await expect(frame.locator("#username")).toHaveValue("");
  await expect(frame.locator("#password")).toHaveValue("");
  await page.close();
});

test("no rellena con una entrada de otro origen", async () => {
  const otherId = await addEntry("Otro", "https://example.com", "eve", "pw-other");
  const page = await context.newPage();
  await page.goto(`${server.base}/login.html`);
  expect(await fill(await tabIdOf(page), otherId)).toEqual({ ok: false, error: "NO_MATCH" });
  await expect(page.locator("#password")).toHaveValue("");
  await page.close();
});

test("genera, guarda y rellena un formulario de registro", async () => {
  const page = await context.newPage();
  await page.goto(`${server.base}/register.html`);
  const r = await hook<{ entryId: string; result: string }>("generateAndFill", { title: "Registro", username: "bob@example.com", options: { length: 24 } }, await tabIdOf(page));
  expect(r.ok && r.data.result).toBe("filled");
  const pw = await page.locator("#new-password").inputValue();
  expect(pw).toHaveLength(24);
  await expect(page.locator("#confirm-password")).toHaveValue(pw);
  await expect(page.locator("#email")).toHaveValue("bob@example.com");
  await page.close();
});

test("ignora los mensajes enviados por páginas web", async () => {
  const page = await context.newPage();
  await page.goto(`${server.base}/message.html?ext=${extId}`);
  await expect(page.locator("body")).toHaveAttribute("data-result", /.+/);
  const result = (await page.locator("body").getAttribute("data-result")) ?? "";
  expect(result).not.toContain("reply:{");
  const st = await hook<{ unlocked: boolean }>("status");
  expect(st.ok && st.data.unlocked).toBe(true);
  await page.close();
});

test("tras bloquear, rellenar falla con LOCKED", async () => {
  const list = (await hook<Array<{ id: string; title: string }>>("list")) as { ok: true; data: Array<{ id: string; title: string }> };
  const id = list.data.find((e) => e.title === "Local")!.id;
  expect((await hook("lock")).ok).toBe(true);
  const page = await context.newPage();
  await page.goto(`${server.base}/login.html`);
  expect(await fill(await tabIdOf(page), id)).toEqual({ ok: false, error: "LOCKED" });
  await expect(page.locator("#password")).toHaveValue("");
  const sessionKeys = await sw.evaluate(async () => Object.keys(await chrome.storage.session.get(null)));
  expect(sessionKeys).toEqual([]);
  await page.close();
});
