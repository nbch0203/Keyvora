// Adapts the raw wasm-bindgen exports to the typed CoreModule contract. No chrome.* here so that
// Node tests can use it with `initSync`.
import type { CoreModule, MatchLevel } from "./types.ts";
import type { WasmBindings } from "./wasm-api.ts";

export function createCoreModule(b: WasmBindings): CoreModule {
  const V = b.WasmVault;
  return {
    create: (master, params, deviceId, nowMs) => V.create(master, params, deviceId, nowMs),
    unlockWithPassword: (container, master, deviceId) => V.unlockWithPassword(container, master, deviceId),
    unlockWithRecoveryKey: (container, rk, deviceId) => V.unlockWithRecoveryKey(container, rk, deviceId),
    openWithDataKey: (container, dek, deviceId) => V.openWithDataKey(container, dek, deviceId),
    generatePassword: (options) => b.generatePassword(options),
    passwordEntropyBits: (options) => b.passwordEntropyBits(options),
    matchLevel: (entryUrl, pageUrl) => b.matchLevel(entryUrl, pageUrl) as MatchLevel,
    pageOrigin: (pageUrl) => b.pageOrigin(pageUrl) ?? undefined,
    defaultKdfParams: () => b.defaultKdfParams(),
    benchmarkKdf: (params) => b.benchmarkKdf(params),
  };
}
