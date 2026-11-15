# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/). Versionado semántico.

## [Unreleased]

### Añadido
- **Diseño (Fases 0/1):** informe de entorno, decisiones ADR-001…014, modelo de amenazas (T1–T22), especificación del
  formato de bóveda v1, contratos entre módulos, protocolo de sincronización, guía OAuth de Google Drive, calibración
  de Argon2id y revisión de seguridad.
- **Núcleo Rust (`packages/`):**
  - `keyvora-crypto`: Argon2id, HKDF-SHA256, AES-256-GCM, CSPRNG, `zeroize` (incl. claves de ronda AES/GHASH).
  - `keyvora-passgen`: generador sin sesgo con CSPRNG.
  - `keyvora-vault`: contenedor versionado con ranuras de contraseña y recuperación; AAD que liga encabezado,
    ranuras y revisión; CRUD con historial causal; recuperación; rotación de DEK con claves retiradas; coincidencia
    de orígenes con la Public Suffix List; el escritor aplica las mismas invariantes que el lector.
  - `keyvora-sync`: fusión CRDT por *dotted version vectors* (sin pérdida) y política de claves `KEYRING_CHANGED`
    + `adopt_remote_keys` (nunca se adoptan claves remotas sin reautenticación).
  - Bindings WASM (wasm-bindgen) y Kotlin (UniFFI 0.28, compatibles con Android y alineados a 16 KB).
- **Extensión MV3 (`apps/browser-extension/`):** popup en español, sesión en `storage.session`, autobloqueo,
  autorrelleno bajo demanda con `activeTab` y validación de origen, generación para registros, conflictos,
  exportación/importación cifrada, rotación de clave, sincronización con Google Drive (`drive.appdata`).
- **Android (`apps/android/`):** Kotlin + Compose, persistencia cifrada atómica, biometría con Keystore, autobloqueo,
  portapapeles sensible, Autofill con confianza por certificado (navegadores TOFU y apps fijadas), sincronización con
  Google Drive, rotación de clave y reautenticación ante claves remotas nuevas.
- **Pruebas:** KAT, seguridad (manipulación, splicing, límites, fugas), propiedades de la fusión (5 000 casos),
  vectores multiplataforma verificados por Rust, WASM, Kotlin y una reimplementación independiente en Python,
  E2E de la extensión en Edge, tests JVM de Android con el núcleo real.
- **Scripts y CI:** entorno Windows/WSL, builds del núcleo, workflow de GitHub Actions (sin ejecutar todavía).

- Android: sugerencia **«Generar contraseña segura»** en el autorrelleno de formularios de registro (genera, guarda la
  entrada y rellena contraseña y confirmación); formulario de registro de pruebas en `autofill-demo`.
- Android: **modo oscuro** con selector en Ajustes → Apariencia (según el sistema, claro u oscuro).
- Android: **«Elegir una entrada de Keyvora»** en el inicio de sesión de apps sin entradas vinculadas (vincula la
  entrada con `androidapp://<paquete>` tras confirmar y fija el certificado); mejor detección de campos con las
  predicciones de Chrome/WebView, etiquetas, *placeholders* y descripciones de accesibilidad.

### Cambiado
- Android: interfaz rediseñada: paleta de marca, iconos de barra de estado legibles (edge-to-edge), bienvenida con
  logotipo, lista con iniciales y botón de copiar contraseña, detalle con acciones por icono, generador plegable con
  chips, Ajustes agrupados en tarjetas, avisos con icono y medidor de fortaleza de la contraseña maestra.
- El modelo de fusión inicial (reloj único por entrada) se sustituyó por *dotted version vectors* tras un
  contraejemplo encontrado por el test de propiedades.

### Seguridad
- Revisión del núcleo (`docs/SECURITY_REVIEW.md`): resueltos H-1 (rotación de DEK), M-1 (escritor seguro y
  contadores), M-2 (adopción de claves con reautenticación), M-3 (confianza del Autofill en Android) y L-1…L-8.
- Verificación independiente de QA (`docs/QA_REPORT.md`) con fuzzing del parser y de la fusión: corregidos
  QA-DEF-001 (suelo del historial por encima del contexto), QA-DEF-002 (claves retiradas más nuevas que el keyring),
  QA-DEF-003 (cambios de claves concurrentes con DEK distintas bloqueaban la sincronización) y QA-DEF-004 (aviso
  `recoveryKeyChanged` cuando la clave de recuperación mostrada deja de valer).
- Auditoría final de los clientes (QA-006, `docs/QA_REPORT.md §12`): Android ya no supone `https` cuando falta
  `webScheme`; el autorrelleno comprueba el autobloqueo con el reloj real; secretos fuera de `rememberSaveable` y
  clave de recuperación con teclado de contraseña. Extensión: confirmación `sameSite` ligada al host mostrado,
  autobloqueo comprobado en cada mensaje y descarga de Drive limitada a 40 MiB.

### Corregido
- Android: tras activar la biometría, el desbloqueo no la ofrecía hasta reiniciar la app (AND-DEF-001, hallado en
  las pruebas en emulador).

### Pruebas
- Pruebas en emulador Android 15: flujo completo, Autofill en app nativa con fijación de certificado y rechazo de
  app impostora, biometría con invalidación, recuperación y compatibilidad cruzada Android ↔ WASM ↔ Python.
- App de pruebas `apps/android/autofill-demo` (no se publica).
- Extensión verificada en Brave 1.99 (7/7) y Firefox 137 (8/8, con `test/e2e/firefox-e2e.mjs` vía WebDriver BiDi);
  mecanismo OAuth (`launchWebAuthFlow`) comprobado en Brave, Edge y Firefox con un endpoint falso local.
- ID de extensión Chromium estable (`omkfgoephodmeehbnnpbejfdpfebaldl`) mediante `key` en el manifiesto de desarrollo;
  `npm run build -- --store` la omite para la Chrome Web Store.
