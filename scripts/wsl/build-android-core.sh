#!/usr/bin/env bash
# Cross-compiles the UniFFI core for Android ABIs and generates the Kotlin bindings.
#   jniLibs → apps/android/app/src/main/jniLibs/<abi>/libkeyvora_ffi.so
#   Kotlin  → apps/android/core-generated/uniffi/keyvora_ffi/keyvora_ffi.kt
set -euo pipefail
source "$(dirname "$0")/env.sh"
cd "$REPO_ROOT"
JNI="apps/android/app/src/main/jniLibs"
GEN="apps/android/core-generated"
rm -rf "$JNI" "$GEN" && mkdir -p "$JNI" "$GEN"
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -t x86 --platform 26 -o "$JNI" build -p keyvora-ffi --release
# Bindings are generated from a host build of the same crate (library mode reads the embedded UniFFI metadata).
cargo build -p keyvora-ffi --release
cargo run -q -p keyvora-ffi --features bindgen --bin uniffi-bindgen -- generate \
  --library "$CARGO_TARGET_DIR/release/libkeyvora_ffi.so" --language kotlin --out-dir "$GEN" --no-format
# Host (Linux) library for the JVM unit tests (CoreVectorsTest runs with -Pkeyvora.requireHostCore=true on Linux/CI).
mkdir -p "$GEN/host" && cp "$CARGO_TARGET_DIR/release/libkeyvora_ffi.so" "$GEN/host/"
find "$JNI" "$GEN" -type f | xargs ls -la
