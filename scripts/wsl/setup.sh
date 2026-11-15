#!/usr/bin/env bash
# One-time Linux toolchain setup for building the Rust core (run INSIDE WSL Ubuntu or any Linux/CI host).
# Prerequisite (needs sudo, run once by the user):  sudo apt update && sudo apt install -y build-essential pkg-config curl unzip
# Everything below is per-user, no sudo. Downloads are verified against published checksums.
set -euo pipefail
log() { echo "[setup $(date +%H:%M:%S)] $*"; }

for c in cc curl unzip sha1sum; do
  command -v "$c" >/dev/null || { echo "Missing '$c'. Run: sudo apt update && sudo apt install -y build-essential pkg-config curl unzip"; exit 1; }
done

# Rust
if ! command -v "$HOME/.cargo/bin/rustup" >/dev/null; then
  log "Installing rustup"
  tmp=$(mktemp -d)
  curl -sSfL -o "$tmp/rustup-init" https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init
  want=$(curl -sSfL https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init.sha256 | awk '{print $1}')
  got=$(sha256sum < "$tmp/rustup-init" | awk '{print $1}')
  [ "$want" = "$got" ] || { echo "rustup checksum mismatch"; exit 1; }
  chmod +x "$tmp/rustup-init"
  "$tmp/rustup-init" -y --profile minimal --default-toolchain stable -c rustfmt -c clippy
fi
export PATH="$HOME/.cargo/bin:$PATH"
rustup target add wasm32-unknown-unknown aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android

# Tools. wasm-bindgen-cli must match the wasm-bindgen version resolved in Cargo.lock exactly.
cd "$(dirname "$0")/../.."
grep -q 'name = "wasm-bindgen"' Cargo.lock 2>/dev/null || cargo generate-lockfile
WB_VERSION=$(awk '/^name = "wasm-bindgen"$/{getline; gsub(/version = |"/,""); print; exit}' Cargo.lock)
if ! wasm-bindgen --version 2>/dev/null | grep -q "$WB_VERSION"; then
  log "Installing wasm-bindgen-cli $WB_VERSION"
  cargo install wasm-bindgen-cli --version "$WB_VERSION" --locked
fi
command -v cargo-ndk >/dev/null || { log "Installing cargo-ndk"; cargo install cargo-ndk --locked; }

# Android NDK r27d (27.3.13750724) for Linux
NDK_DIR="$HOME/android-ndk-r27d"
if [ ! -d "$NDK_DIR" ]; then
  ZIP="$HOME/ndk-r27d.zip"
  if [ ! -f "$ZIP" ]; then
    log "Downloading Android NDK r27d"
    curl -sSfL -o "$ZIP.part" https://dl.google.com/android/repository/android-ndk-r27d-linux.zip
    mv "$ZIP.part" "$ZIP"
  fi
  got=$(sha1sum < "$ZIP" | awk '{print $1}')
  [ "$got" = "22105e410cf29afcf163760cc95522b9fb981121" ] || { echo "NDK checksum mismatch"; rm -f "$ZIP"; exit 1; }
  unzip -q "$ZIP" -d "$HOME" && rm -f "$ZIP"
fi
log "OK: $(rustc --version); $(wasm-bindgen --version); cargo-ndk $(cargo ndk --version 2>/dev/null | head -1); NDK at $NDK_DIR"
