// Manifest variants derived from the single source manifest.json (Chromium).
// Kept as pure functions so that unit tests can check permissions of every variant.

export const REQUIRED_PERMISSIONS = ["storage", "alarms", "activeTab", "scripting", "identity"];
export const FORBIDDEN_KEYS = ["host_permissions", "optional_host_permissions", "content_scripts", "externally_connectable", "web_accessible_resources"];
export const FIREFOX_ID = "{6f1c0a64-0a3e-4b9a-9a53-2f2d7f6f2b1e}";
export const E2E_HOSTS = ["http://127.0.0.1/*", "http://localhost/*"];

const clone = (o) => JSON.parse(JSON.stringify(o));

/** Throws if the base manifest drifts from the security decisions of ADR-009. */
export function assertBaseManifest(m) {
  const perms = [...(m.permissions ?? [])].sort();
  if (JSON.stringify(perms) !== JSON.stringify([...REQUIRED_PERMISSIONS].sort())) {
    throw new Error(`manifest.json: los permisos deben ser exactamente ${REQUIRED_PERMISSIONS.join(", ")}`);
  }
  for (const k of FORBIDDEN_KEYS) if (k in m) throw new Error(`manifest.json: clave prohibida "${k}"`);
  const csp = m.content_security_policy?.extension_pages;
  if (csp !== "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'") throw new Error("manifest.json: CSP inesperada");
  if (m.background?.service_worker !== "background.js" || m.background?.type !== "module") throw new Error("manifest.json: background inesperado");
}

export function chromiumManifest(base) {
  assertBaseManifest(base);
  return clone(base);
}

export function firefoxManifest(base) {
  assertBaseManifest(base);
  const m = clone(base);
  delete m.minimum_chrome_version;
  m.background = { scripts: ["background.js"], type: "module" };
  m.browser_specific_settings = {
    gecko: {
      id: FIREFOX_ID,
      strict_min_version: "128.0",
      data_collection_permissions: { required: ["none"] },
    },
  };
  return m;
}

/** E2E only: grants scripting on the local test server without a user gesture. Never shipped. */
export function e2eManifest(base) {
  const m = chromiumManifest(base);
  m.name = `${m.name} (E2E)`;
  m.host_permissions = [...E2E_HOSTS];
  return m;
}
