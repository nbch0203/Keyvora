# Keyvora (Password Transformer)

Gestor de contraseñas *local-first* con bóveda cifrada, app Android, extensión de navegador y sincronización cifrada
mediante Google Drive. El usuario recuerda una sola contraseña maestra; cada servicio usa una contraseña aleatoria
única guardada en la bóveda.

> Estado: desarrollo (Fases 0–2 diseñadas e implementadas, clientes en curso). Consulta [`TASKS.md`](TASKS.md).
> No uses esta versión con contraseñas reales hasta superar la auditoría de la Fase 6.

## Estructura

```text
packages/
  crypto-core/        Argon2id, HKDF, AES-256-GCM, CSPRNG (RustCrypto)          — keyvora-crypto
  password-generator/ Generador sin sesgo (muestreo por rechazo)                  — keyvora-passgen
  vault-core/         Formato v1, ranuras de clave, CRUD, recuperación, orígenes  — keyvora-vault
  sync-core/          Fusión CRDT sin pérdida (relojes vectoriales)               — keyvora-sync
  bindings-wasm/      API para la extensión (wasm-bindgen)                        — keyvora-wasm
  bindings-uniffi/    API Kotlin para Android (UniFFI)                            — keyvora-ffi
  shared-models/      Tipos TS del contrato y vectores de prueba multiplataforma
apps/
  browser-extension/  Manifest V3 (Chromium; Firefox evaluado)
  android/            Kotlin + Jetpack Compose + Autofill
infrastructure/google-drive/  Configuración OAuth sin secretos
tests/security/       Verificación independiente del formato (Python, otras bibliotecas)
docs/                 Arquitectura, decisiones, contratos, formato, amenazas, sync
scripts/              Entorno (Windows/WSL) y builds del núcleo
```

## Documentación

| Documento | Contenido |
|---|---|
| [docs/DECISIONS.md](docs/DECISIONS.md) | Decisiones de arquitectura validadas y alternativas descartadas |
| [docs/VAULT_FORMAT.md](docs/VAULT_FORMAT.md) | Especificación del contenedor cifrado v1 |
| [docs/CONTRACTS.md](docs/CONTRACTS.md) | Contratos Core / WASM / Kotlin / mensajería / sync |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Modelo de amenazas y pruebas obligatorias |
| [docs/SYNC_PROTOCOL.md](docs/SYNC_PROTOCOL.md) | Fusión y protocolo con Drive |
| [docs/BUILD.md](docs/BUILD.md) | Entorno, compilación, pruebas, CI y checklist de release |
| [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md) | Revisión de seguridad del núcleo y su resolución |
| [docs/QA_REPORT.md](docs/QA_REPORT.md) | Verificación independiente de QA y trazabilidad |
| [TASKS.md](TASKS.md) | Estado de cada tarea con su evidencia |
| [password-transformer-plan/](password-transformer-plan/README.md) | Plan original (instrucciones, requisitos de seguridad, roadmap) |
| [infrastructure/google-drive/README.md](infrastructure/google-drive/README.md) | Proyecto Google Cloud y OAuth |

## Seguridad en una línea

Argon2id (64 MiB) deriva una KEK que envuelve una DEK aleatoria; la DEK cifra la bóveda con AES-256-GCM autenticando
encabezado, ranuras y revisión. La contraseña maestra nunca se guarda ni se transmite; Drive solo recibe el contenedor
cifrado. La recuperación usa una clave independiente de 256 bits que se muestra una sola vez.
