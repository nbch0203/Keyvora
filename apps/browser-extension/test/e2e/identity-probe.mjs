// Checks that chrome.identity.launchWebAuthFlow works in a Chromium-based browser (e.g. Brave, which removes Google
// account services) without contacting Google: a local fake OAuth endpoint redirects to the extension's
// chromiumapp.org redirect URL with a fake implicit-flow token.
// Usage: node test/e2e/identity-probe.mjs "<path to brave.exe | msedge.exe>"   (after `npm run build:e2e`)
import { chromium } from "@playwright/test";
import { mkdtempSync, rmSync } from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const executablePath = process.argv[2];
const ext = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "dist", "e2e");
const server = http.createServer((req, res) => {
  const u = new URL(req.url, "http://127.0.0.1");
  const redirect = u.searchParams.get("redirect_uri");
  res.writeHead(302, { Location: `${redirect}#access_token=fake-token-123&token_type=Bearer&expires_in=3600&state=${u.searchParams.get("state")}` });
  res.end();
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const port = server.address().port;
const dir = mkdtempSync(path.join(os.tmpdir(), "keyvora-identity-"));
const ctx = await chromium.launchPersistentContext(dir, {
  executablePath,
  args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`],
});
try {
  const sw = ctx.serviceWorkers()[0] ?? (await ctx.waitForEvent("serviceworker"));
  const result = await sw.evaluate(async (p) => {
    const out = { hasIdentity: typeof chrome.identity?.launchWebAuthFlow === "function", redirect: chrome.identity?.getRedirectURL?.() ?? null };
    try {
      const url = `http://127.0.0.1:${p}/auth?redirect_uri=${encodeURIComponent(out.redirect)}&state=xyz`;
      const final = await chrome.identity.launchWebAuthFlow({ url, interactive: false });
      const h = new URLSearchParams(new URL(final).hash.slice(1));
      return { ...out, ok: true, token: h.get("access_token"), state: h.get("state") };
    } catch (e) {
      return { ...out, ok: false, error: String(e?.message ?? e) };
    }
  }, port);
  console.log(JSON.stringify({ browser: path.basename(executablePath), ...result }));
} finally {
  await ctx.close();
  server.close();
  rmSync(dir, { recursive: true, force: true });
}
