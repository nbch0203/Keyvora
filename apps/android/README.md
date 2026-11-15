# Keyvora — Android

Cliente Android (Kotlin, Jetpack Compose, MVVM, corrutinas) del gestor de contraseñas Keyvora. Toda la criptografía,
el formato de bóveda, la fusión de sincronización y la coincidencia de orígenes viven en el núcleo Rust compartido
(`packages/*`), al que la app llama a través de `com.keyvora.app.core.CoreBridge` (UniFFI). Kotlin no reimplementa
nada de eso.

## Compilar y probar

Requisitos: JDK 17, Android SDK (`platforms;android-35`, `build-tools;35.0.0`). En este repo (Git Bash):

```bash
source scripts/env.sh                 # JAVA_HOME, ANDROID_HOME, Gradle
cd apps/android
echo "sdk.dir=$(cygpath -m "$ANDROID_HOME")" > local.properties   # solo la primera vez (gitignored)
./gradlew :app:assembleDebug :app:testDebugUnitTest :app:lintDebug
```

APK: `app/build/outputs/apk/debug/app-debug.apk`. Versiones fijadas en `gradle/libs.versions.toml`
(AGP 8.9.1, Kotlin 2.1.20, Gradle 8.13, compile/target SDK 35, minSdk 26, JNA 5.18.1). Todas las librerías nativas del
APK (`libkeyvora_ffi.so`, `libjnidispatch.so`) tienen segmentos alineados a 16 KB.

## Núcleo Rust (UniFFI)

El build elige el *source set* según exista `core-generated/uniffi/keyvora_ffi/keyvora_ffi.kt`:

| Estado | Source set | Comportamiento |
|---|---|---|
| Bindings generados | `app/src/uniffi` + `core-generated/` | `UniffiCoreBridge` sobre `uniffi.keyvora_ffi` y `libkeyvora_ffi.so` (JNA) |
| Sin bindings | `app/src/nocore` | `NoCoreBridge`: toda llamada lanza `CoreException("CORE_NOT_BUILT")`; la UI lo indica |

Ambos definen `com.keyvora.app.core.CoreBridgeFactory`. `BuildConfig.CORE_AVAILABLE` refleja el estado.
Los artefactos los genera el orquestador (WSL, `scripts/wsl/build-android-core.sh`, `cargo-ndk` + `uniffi-bindgen` en
modo librería):

- `app/src/main/jniLibs/<abi>/libkeyvora_ffi.so` (arm64-v8a, armeabi-v7a, x86, x86_64; gitignored)
- `core-generated/uniffi/keyvora_ffi/keyvora_ffi.kt`

`CoreVectorsTest` verifica con el núcleo real los vectores `packages/shared-models/test-vectors/vault-v1.json`
(desbloqueo con contraseña, variante NFD, clave de recuperación, DEK, coincidencia de orígenes). En la JVM de tests
necesita una compilación **del host** del núcleo en `core-generated/host/` (`libkeyvora_ffi.so` en Linux,
`keyvora_ffi.dll` en Windows). Sin ella el test se omite con un mensaje; `-Pkeyvora.requireHostCore=true` lo convierte
en fallo (para CI en Linux).

## Google Drive (OAuth)

Ver `infrastructure/google-drive/README.md`. Resumen para Android:

- Scope único `https://www.googleapis.com/auth/drive.appdata` (carpeta oculta `appDataFolder`).
- Google Identity Services `AuthorizationClient`; **no hay client secret en el APK**.
- Hay que crear un cliente OAuth de tipo **Android** con el paquete `com.keyvora.app` y el SHA-1 del certificado de
  firma (debug: `keytool -list -v -keystore ~/.android/debug.keystore -alias androiddebugkey -storepass android`) en el
  **mismo proyecto de Google Cloud** que el cliente web de la extensión; si no, no comparten `appDataFolder`.
- Solo se sube el contenedor cifrado (`keyvora-vault.json`). Protocolo: `docs/SYNC_PROTOCOL.md` (implementado en
  `sync/SyncEngine.kt`).

## Activar el autorrelleno en un dispositivo

1. Ajustes del sistema → Contraseñas y cuentas (o Sistema → Idiomas y entrada → Servicio de autocompletar) →
   elegir **Keyvora**.
2. Chrome: Ajustes → Servicios de autocompletar → «Autocompletar con otro servicio».
3. Confianza (CONTRACTS §4.1, ADR-014): `webDomain` solo se usa si el paquete está en la lista de navegadores conocidos
   (`AutofillTrust.KNOWN_BROWSERS`) **y** su certificado de firma (SHA-256) coincide con el fijado tras confirmarlo
   la primera vez (TOFU). En cualquier otra app se ignora `webDomain` y solo cuentan las entradas
   `androidapp://<paquete>`; el certificado de la app se fija al asociarla por primera vez (rellenar o guardar con
   confirmación). Si un certificado cambia, no se rellena y se muestra un aviso. Los certificados fijados son locales
   (no se sincronizan) y se gestionan en Ajustes → «Apps y navegadores de confianza».
4. Coincidencia (núcleo): exacta → se ofrece; mismo dominio registrable → solo tras una confirmación que muestra el
   host real. Un navegador sin `webDomain` nunca se rellena; los iframes de otro dominio tampoco.

## Diseño de seguridad (resumen)

- Disco: solo el contenedor cifrado en `filesDir/vault.json` (`AtomicFile`), exportado tras cada cambio.
  `allowBackup=false` + `dataExtractionRules`/`fullBackupContent` que excluyen todo. Preferencias = datos no secretos
  (id de dispositivo, ajustes, estado de sync).
- Contraseña maestra: mínimo 12 caracteres (tras NFC), igual que el núcleo (`MasterPasswordPolicy`).
- Claves remotas (ADR-013): si otro dispositivo cambió la contraseña o rotó la clave de cifrado, `mergeRemote` falla
  con `KEYRING_CHANGED`; la sincronización se detiene sin subir nada, se conserva el contenedor remoto y la app pide
  la contraseña maestra actual para `adoptRemoteKeys` (avisa si los parámetros KDF son más débiles). Igual al importar
  una copia con claves más nuevas.
- Rotación de la clave de cifrado (Ajustes): nueva DEK y nueva clave de recuperación (pantalla de confirmación). Solo
  protege los datos futuros. Si la DEK cambia (aquí o adoptada), se desactiva la biometría y se pide reactivarla.
- Sesión: un único `VaultSession` en memoria (`VaultManager`), serializado con un `Mutex`; `lock()` borra la DEK en
  Rust y suelta la referencia. Autobloqueo en segundo plano (inmediato/1/5/15 min, `ProcessLifecycleOwner`) y por
  inactividad (mínimo 1 min).
- `FLAG_SECURE` y `setRecentsScreenshotEnabled(false)` en todas las actividades.
- Portapapeles: marcado sensible (`android.content.extra.IS_SENSITIVE`), limpieza a los 30 s y al bloquear si el clip
  sigue siendo nuestro.
- Biometría opcional: clave AES-256-GCM del AndroidKeyStore (autenticación BIOMETRIC_STRONG por uso, invalidada al
  registrar huellas) que cifra una copia de la DEK ligada al id de bóveda; nunca se sincroniza.
- Manifest: permisos `INTERNET`, `USE_BIOMETRIC` (+ `USE_FINGERPRINT` limitado a API ≤ 27, requerido por
  androidx.biometric); solo la actividad principal y el servicio de autorrelleno están exportados.
- Sin logs de secretos (`NoSecretLogsTest`); `toString()` de los modelos con secretos está redactado.

## Limitaciones conocidas

- **Probado en emulador (Android 15 x86_64), no en teléfono físico:** flujo completo, Autofill en app nativa con
  fijación de certificado, `FLAG_SECURE`, BiometricPrompt/Keystore y recuperación. Sin probar: relleno web en
  Chrome ≥ 135 (el servicio no usa el modo compatibilidad), SAF y el flujo OAuth real.
- `autofill-demo/` es una app de pruebas con un formulario de login para ejercitar el Autofill (no se publica):
  `./gradlew :autofill-demo:assembleDebug`.
- Parámetros Argon2id por defecto del núcleo (ADR-005) sin medir en un Android real.
- Sin `ACCESS_NETWORK_STATE`: no hay sincronización al recuperar la red; se sincroniza al desbloquear, tras cambios
  (3 s de *debounce*), manualmente y con reintento cada 5 min mientras haya cambios pendientes.
- La limpieza del portapapeles depende de que el proceso viva; si el sistema lo congela, se limpia al volver a primer
  plano.
- Textos de la UI en español escritos directamente en Compose (sin `strings.xml` salvo etiquetas del sistema).
- Visibilidad de paquetes: `<queries>` con la intención LAUNCHER (para leer el certificado de la app que pide el
  autorrelleno, sin `QUERY_ALL_PACKAGES`); una app sin actividad de inicio no se puede verificar y no se rellena.
- Tras rotar la clave de cifrado, las copias o versiones de Drive anteriores ya no se pueden previsualizar/restaurar
  con la clave nueva.
