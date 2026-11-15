#!/usr/bin/env node
// Keyvora extension build (esbuild only; no other native tools).
//
//   node scripts/build.mjs           → dist/chromium + dist/firefox (requires src/core/pkg, fails loudly otherwise)
//   node scripts/build.mjs --e2e     → dist/e2e (Chromium + test hook + host_permissions for 127.0.0.1/localhost)
//   node scripts/build.mjs --check   → dist/check (bundles with a stub core when src/core/pkg is missing; NOT loadable)
//
// Env: KEYVORA_GOOGLE_CLIENT_ID (optional) — OAuth client id for Google Drive sync; empty → "no configurado".
import { build } from "esbuild";
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ICON_SIZES, iconPng } from "./icons.mjs";
import { chromiumManifest, e2eManifest, firefoxManifest } from "./manifest.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const args = new Set(process.argv.slice(2));
const mode = args.has("--e2e") ? "e2e" : args.has("--check") ? "check" : "release";
const dist = path.join(root, "dist");
const pkgDir = path.join(root, "src", "core", "pkg");
const wasmJs = path.join(pkgDir, "keyvora_wasm.js");
const wasmBin = path.join(pkgDir, "keyvora_wasm_bg.wasm");
const hasPkg = existsSync(wasmJs) && existsSync(wasmBin);

function fail(msg) {
  console.error(`\n[keyvora build] ERROR: ${msg}\n`);
  process.exit(1);
}

if (!hasPkg && mode !== "check") {
  fail(
    "falta el núcleo WASM en src/core/pkg/ (keyvora_wasm.js y keyvora_wasm_bg.wasm).\n" +
      "  Genéralo desde la raíz del repositorio (WSL/Linux):  bash scripts/wsl/build-wasm.sh\n" +
      "  Para validar typecheck + bundling sin el núcleo usa:   npm run build:check",
  );
}

const clientId = (process.env.KEYVORA_GOOGLE_CLIENT_ID ?? "").trim();
if (clientId && !/^[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com$/.test(clientId)) {
  fail("KEYVORA_GOOGLE_CLIENT_ID no tiene el formato <número>-<id>.apps.googleusercontent.com");
}

/** Replaces the missing wasm-bindgen module with a stub that always fails (only for --check). */
const stubCorePlugin = {
  name: "keyvora-stub-core",
  setup(b) {
    b.onResolve({ filter: /\/pkg\/keyvora_wasm\.js$/ }, () => ({ path: "keyvora-wasm-stub", namespace: "keyvora-stub" }));
    b.onLoad({ filter: /.*/, namespace: "keyvora-stub" }, () => ({
      loader: "js",
      contents: `const missing = () => { throw new Error("CORE_UNAVAILABLE"); };
export default async function init() { missing(); }
export const initSync = missing, generatePassword = missing, passwordEntropyBits = missing, matchLevel = missing,
  pageOrigin = missing, defaultKdfParams = missing, benchmarkKdf = missing;
export class WasmVault { static create() { missing(); } static unlockWithPassword() { missing(); }
  static unlockWithRecoveryKey() { missing(); } static openWithDataKey() { missing(); } }`,
    }));
  },
};

async function bundle(outdir, { test }) {
  await build({
    absWorkingDir: root,
    entryPoints: { background: "src/background/index.ts", popup: "src/popup/main.ts" },
    outdir,
    bundle: true,
    format: "esm",
    platform: "browser",
    target: ["chrome120", "firefox128"],
    // Syntax minification enables dead-code elimination of the test hook; identifiers stay readable for review.
    minifySyntax: true,
    keepNames: false, // keepNames would inject a module-level helper into the self-contained injected functions
    sourcemap: false,
    legalComments: "none",
    charset: "utf8",
    logLevel: "warning",
    define: {
      __KEYVORA_TEST__: test ? "true" : "false",
      __KEYVORA_GOOGLE_CLIENT_ID__: JSON.stringify(clientId),
    },
    plugins: hasPkg ? [] : [stubCorePlugin],
  });
}

function copyStatic(outdir, manifest) {
  cpSync(path.join(root, "static"), outdir, { recursive: true });
  mkdirSync(path.join(outdir, "icons"), { recursive: true });
  for (const s of ICON_SIZES) writeFileSync(path.join(outdir, "icons", `icon-${s}.png`), iconPng(s));
  if (hasPkg) {
    mkdirSync(path.join(outdir, "core"), { recursive: true });
    cpSync(wasmBin, path.join(outdir, "core", "keyvora_wasm_bg.wasm"));
  }
  writeFileSync(path.join(outdir, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
}

function verify(outdir, { test }) {
  const bg = readFileSync(path.join(outdir, "background.js"), "utf8");
  const popup = readFileSync(path.join(outdir, "popup.js"), "utf8");
  if (!test && (bg.includes("__keyvoraTest") || popup.includes("__keyvoraTest"))) {
    fail(`el gancho de pruebas __keyvoraTest apareció en una build normal (${outdir})`);
  }
  if (test && !bg.includes("__keyvoraTest")) fail("la build E2E no contiene el gancho de pruebas");
  for (const [name, code] of [["background.js", bg], ["popup.js", popup]]) {
    if (/\bconsole\.log\(/.test(code)) fail(`${name} contiene console.log (prohibido: riesgo de filtrar secretos)`);
    if (/\beval\(|new Function\(/.test(code)) fail(`${name} contiene eval/new Function`);
  }
}

const base = JSON.parse(readFileSync(path.join(root, "manifest.json"), "utf8"));

async function target(name, manifest, { test }) {
  const outdir = path.join(dist, name);
  rmSync(outdir, { recursive: true, force: true });
  mkdirSync(outdir, { recursive: true });
  await bundle(outdir, { test });
  copyStatic(outdir, manifest);
  verify(outdir, { test });
  return outdir;
}

try {
  if (mode === "release") {
    const c = await target("chromium", chromiumManifest(base), { test: false });
    const f = await target("firefox", firefoxManifest(base), { test: false });
    writeFileSync(path.join(dist, "manifest.firefox.json"), `${JSON.stringify(firefoxManifest(base), null, 2)}\n`);
    console.log(`[keyvora build] OK → ${path.relative(root, c)}, ${path.relative(root, f)}${clientId ? "" : " (sincronización: no configurada)"}`);
  } else if (mode === "e2e") {
    const e = await target("e2e", e2eManifest(base), { test: true });
    console.log(`[keyvora build] OK (E2E) → ${path.relative(root, e)}`);
  } else {
    const outdir = path.join(dist, "check");
    rmSync(outdir, { recursive: true, force: true });
    await target(path.join("check", "chromium"), chromiumManifest(base), { test: false });
    await target(path.join("check", "firefox"), firefoxManifest(base), { test: false });
    console.log(
      `[keyvora build] OK (check) → dist/check ${hasPkg ? "(con núcleo WASM)" : "(núcleo WASM AUSENTE: bundle con stub, no cargable en el navegador)"}`,
    );
  }
} catch (e) {
  fail(e instanceof Error ? e.message : String(e));
}
