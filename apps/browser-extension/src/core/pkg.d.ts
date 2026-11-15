// Declaration stub for the wasm-bindgen output (src/core/pkg/keyvora_wasm.js), which is produced later by
// scripts/wsl/build-wasm.sh. When the real package exists TypeScript resolves the generated file instead; the
// loader only relies on the shape declared in wasm-api.ts, so both cases typecheck.
declare module "*/pkg/keyvora_wasm.js" {
  const init: (init?: { module_or_path: unknown }) => Promise<unknown>;
  export default init;
  export function initSync(init: { module: unknown }): unknown;
  export const WasmVault: unknown;
  export function generatePassword(options?: unknown): string;
  export function passwordEntropyBits(options?: unknown): number;
  export function matchLevel(entryUrl: string, pageUrl: string): string;
  export function pageOrigin(pageUrl: string): string | undefined;
  export function defaultKdfParams(): unknown;
  export function benchmarkKdf(params: unknown): void;
}
