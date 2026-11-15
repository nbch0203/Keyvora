// Loads the real WASM core in Node (initSync) when src/core/pkg exists; otherwise tests are skipped with a message.
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createCoreModule } from "../../../src/core/adapter.ts";
import type { CoreModule, KdfParams } from "../../../src/core/types.ts";
import type { WasmBindings } from "../../../src/core/wasm-api.ts";

export const EXT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
export const PKG_DIR = path.join(EXT_ROOT, "src", "core", "pkg");
export const VECTORS = path.resolve(EXT_ROOT, "..", "..", "packages", "shared-models", "test-vectors", "vault-v1.json");

export const SKIP_NO_CORE =
  "núcleo WASM ausente (apps/browser-extension/src/core/pkg): genéralo con `bash scripts/wsl/build-wasm.sh` y vuelve a ejecutar los tests";

/** Lowest parameters accepted by the core (ADR-005) to keep tests fast. Never used outside tests. */
export const FAST_KDF: KdfParams = { memoryKiB: 19 * 1024, iterations: 2, parallelism: 1 };

let cached: Promise<CoreModule | null> | null = null;

export function loadRealCore(): Promise<CoreModule | null> {
  if (!cached) {
    cached = (async () => {
      const js = path.join(PKG_DIR, "keyvora_wasm.js");
      const wasm = path.join(PKG_DIR, "keyvora_wasm_bg.wasm");
      if (!existsSync(js) || !existsSync(wasm)) return null;
      const mod = (await import(pathToFileURL(js).href)) as unknown as WasmBindings;
      mod.initSync({ module: readFileSync(wasm) });
      return createCoreModule(mod);
    })();
  }
  return cached;
}

/** Same core with fast KDF parameters for create/change operations. */
export function withFastKdf(core: CoreModule): CoreModule {
  return { ...core, defaultKdfParams: () => ({ ...FAST_KDF }) };
}
