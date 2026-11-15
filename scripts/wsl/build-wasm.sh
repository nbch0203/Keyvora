#!/usr/bin/env bash
# Builds the WASM core for the browser extension into apps/browser-extension/src/core/pkg/.
set -euo pipefail
source "$(dirname "$0")/env.sh"
cd "$REPO_ROOT"
cargo build -p keyvora-wasm --release --target wasm32-unknown-unknown
OUT="apps/browser-extension/src/core/pkg"
rm -rf "$OUT" && mkdir -p "$OUT"
wasm-bindgen --target web --out-dir "$OUT" --out-name keyvora_wasm "$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/keyvora_wasm.wasm"
ls -la "$OUT"
