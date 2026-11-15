// WASM core loader for the extension (service worker). Initializes the module once from the packaged
// `core/keyvora_wasm_bg.wasm` and exposes the typed CoreModule.
import * as wasm from "./pkg/keyvora_wasm.js";
import { createCoreModule } from "./adapter.ts";
import type { CoreModule } from "./types.ts";
import type { WasmBindings } from "./wasm-api.ts";

export const WASM_PATH = "core/keyvora_wasm_bg.wasm";

let loading: Promise<CoreModule> | null = null;

/** Loads the core once. Rejects with `CORE_UNAVAILABLE` (never with internal details). */
export function loadCore(): Promise<CoreModule> {
  if (!loading) {
    const bindings = wasm as unknown as WasmBindings;
    loading = bindings
      .default({ module_or_path: chrome.runtime.getURL(WASM_PATH) })
      .then(() => createCoreModule(bindings))
      .catch(() => {
        loading = null;
        throw new Error("CORE_UNAVAILABLE");
      });
  }
  return loading;
}
