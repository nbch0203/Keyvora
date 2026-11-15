# Keyvora — extensión de navegador (Manifest V3)

Popup + service worker en TypeScript sobre el núcleo Rust compilado a WASM (`packages/bindings-wasm`). La extensión no
reimplementa criptografía, formato, fusión ni coincidencia de orígenes: todo eso lo hace el núcleo.

- Permisos: exactamente `storage`, `alarms`, `activeTab`, `scripting`, `identity` (ADR-009). Sin `host_permissions`,
  content scripts, `externally_connectable` ni `web_accessible_resources`. CSP:
  `script-src 'self' 'wasm-unsafe-eval'; object-src 'self'`. El build falla si el manifiesto se desvía.
- Sesión: contenedor cifrado en `storage.local`; la DEK del desbloqueo solo en `storage.session` (`TRUSTED_CONTEXTS`).
  Autobloqueo por inactividad con `chrome.alarms` (5 min por defecto, 1–60). Bloquear = `lock()` + `free()` y borrar
  `storage.session`.
- Autorrelleno solo al pulsar «Rellenar» en el popup: inyección con `scripting.executeScript` en el frame principal
  (`frameIds: [0]`); la función inyectada aborta si `location.origin` no es el esperado o si no es el frame superior.
  Coincidencias `sameSite` piden confirmación mostrando el host real (aviso si es IDN). Nunca se rellenan iframes.
- Sincronización opcional con Google Drive (`appDataFolder`, scope `drive.appdata`), protocolo de
  `docs/SYNC_PROTOCOL.md` (`src/sync/engine.ts`).
- Política de claves (ADR-013): si otro dispositivo cambió la contraseña maestra o rotó la clave de cifrado, la
  sincronización se detiene (`KEYRING_CHANGED`) y el popup pide la contraseña maestra vigente (`sync.adoptRemoteKeys`);
  nunca se adoptan claves en silencio. *Ajustes → Clave de cifrado* rota la DEK (`rotateDataKey`, sincronizando antes)
  y emite una clave de recuperación nueva. Contraseña maestra nueva: mínimo 12 caracteres.

## Requisitos

- Node ≥ 22.18 (probado con Node 24) y npm.
- El núcleo WASM en `src/core/pkg/` (`keyvora_wasm.js`, `keyvora_wasm_bg.wasm`), generado desde la raíz del repo en
  WSL/Linux con `bash scripts/wsl/build-wasm.sh`. No se versiona.

## Comandos

| Comando | Qué hace |
|---|---|
| `npm install` | Dependencias de desarrollo (esbuild, TypeScript, Playwright, tipos). |
| `npm run typecheck` | `tsc --noEmit` estricto (funciona también sin `src/core/pkg`, gracias a `src/core/pkg.d.ts`). |
| `npm run build` | `dist/chromium/` y `dist/firefox/` (+ `dist/manifest.firefox.json`). **Falla** con un mensaje claro si falta `src/core/pkg`. |
| `npm run build:check` | Typecheck + bundling en `dist/check/`; sin `src/core/pkg` usa un stub del núcleo (no cargable). Para CI. |
| `npm test` | Tests unitarios (`node --test` sobre `test/unit/**/*.test.ts`). Los que necesitan el núcleo real se omiten con un mensaje si falta `src/core/pkg`. |
| `npm run build:e2e` | `dist/e2e/`: igual que Chromium + `host_permissions` para `127.0.0.1`/`localhost` y el gancho `__keyvoraTest`. **Nunca** se distribuye. |
| `npm run test:e2e` | `build:e2e` + Playwright (`test/e2e/`). Requiere `npx playwright install chromium`. |

E2E en Windows con Smart App Control: el Chromium de Playwright (sin firma) queda bloqueado. Se puede usar un navegador
Chromium firmado: `KEYVORA_E2E_EXECUTABLE="C:\ruta\a\msedge.exe" npm run test:e2e` (o `KEYVORA_E2E_CHANNEL=msedge`).

## Instalar sin empaquetar

**Brave / Chrome / Edge:** `npm run build` → abrir `brave://extensions` (o `chrome://extensions`, `edge://extensions`)
→ activar *Modo de desarrollador* → *Cargar descomprimida* → elegir `dist/chromium`. Probado en Brave 1.99 y Edge 157
(Chromium 157): E2E 7/7 y `identity.launchWebAuthFlow` operativo (Brave no admite `getAuthToken`, que no se usa).

El build sin empaquetar fija la clave pública `key` en el manifiesto, así que el ID es siempre
`omkfgoephodmeehbnnpbejfdpfebaldl` (no cambia con la carpeta ni entre navegadores Chromium) y la URI de redirección OAuth
no hay que volver a registrarla. `npm run build -- --store` genera el paquete para la Chrome Web Store sin `key`.

**Firefox (≥ 128):** `npm run build` → `about:debugging#/runtime/this-firefox` → *Cargar complemento temporal* →
elegir `dist/firefox/manifest.json`. Probado en Firefox 137: E2E 8/8. En Firefox de publicación una extensión sin firmar
solo se carga de forma temporal (se quita al cerrar); para instalarla de forma permanente hay que firmarla en AMO
(distribución propia o pública). `storage.session.setAccessLevel` no existe en Firefox y se omite.

## Pruebas E2E por navegador

```bash
npm run build:e2e
# Chromium (CI) / Edge / Brave en Windows con Smart App Control (usa el navegador firmado instalado):
KEYVORA_E2E_EXECUTABLE="C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe" npm run test:e2e
# Firefox (web-ext + puppeteer-core por WebDriver BiDi; herramientas fuera del proyecto):
npm i --prefix <tools> web-ext@8 puppeteer-core@24
KEYVORA_E2E_TOOLS=<tools>/node_modules KEYVORA_FIREFOX="<ruta a firefox.exe>" node test/e2e/firefox-e2e.mjs
# Mecanismo OAuth en un navegador Chromium, contra un endpoint OAuth falso local (no contacta con Google):
node test/e2e/identity-probe.mjs "<ruta a brave.exe o msedge.exe>"
```

Todas usan un perfil temporal nuevo: no tocan el perfil, las extensiones ni las contraseñas del navegador del usuario.

## Sincronización con Google Drive (opcional)

El ID de cliente OAuth se inyecta en tiempo de build; sin él la sección de sincronización muestra «No configurado».

```bash
KEYVORA_GOOGLE_CLIENT_ID=1234-abc.apps.googleusercontent.com npm run build
```

Crear el proyecto de Google Cloud y el cliente OAuth (*Aplicación web*, URI de redirección
`https://omkfgoephodmeehbnnpbejfdpfebaldl.chromiumapp.org/` para Brave/Chrome/Edge y
`https://4d66f48cc866b358a5cdd3763e222aab9c54798d.extensions.allizom.org/` para Firefox) siguiendo
[`infrastructure/google-drive/README.md`](../../infrastructure/google-drive/README.md). La extensión usa el flujo
implícito de `identity.launchWebAuthFlow` (sin client secret); el token de acceso vive solo en `storage.session`.
Android y la extensión deben usar el **mismo** proyecto de Google Cloud (ADR-008).

Segundo dispositivo: en la pantalla inicial, «Ya uso Keyvora: conectar Google Drive» descarga la bóveda cifrada y pide la
contraseña maestra. También se puede restaurar desde una copia cifrada exportada.

## Estructura

```text
manifest.json            manifiesto fuente (Chromium); variantes en scripts/manifest.mjs
scripts/build.mjs        build con esbuild (+ iconos generados, verificación del bundle)
static/                  popup.html, popup.css
src/core/                cargador del WASM, adaptador tipado (CoreModule), stub de tipos del pkg
src/background/          service worker: sesión, autobloqueo, handlers, inyección, controlador de sync
src/sync/                RemoteStore, GoogleDriveRemoteStore, OAuth, InMemoryRemoteStore, SyncEngine
src/popup/               UI (TS + DOM, sin framework)
test/unit/               node --test
test/e2e/                Playwright + servidor local de fixtures
```
