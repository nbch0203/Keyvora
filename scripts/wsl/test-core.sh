#!/usr/bin/env bash
# Format, lint and test the Rust workspace; regenerate the cross-platform test vectors.
set -euo pipefail
source "$(dirname "$0")/env.sh"
cd "$REPO_ROOT"
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --exclude keyvora-wasm -- -D warnings
cargo clippy -p keyvora-wasm --target wasm32-unknown-unknown -- -D warnings
cargo test --workspace --exclude keyvora-wasm
mkdir -p packages/shared-models/test-vectors
if [ "${REGENERATE_VECTORS:-0}" = "1" ] || [ ! -f packages/shared-models/test-vectors/vault-v1.json ]; then
  cargo run -q -p keyvora-vault --example gen_vectors -- packages/shared-models/test-vectors/vault-v1.json
fi
cargo test -p keyvora-vault --test vectors
