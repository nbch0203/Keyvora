#!/usr/bin/env bash
# Environment for Linux/WSL builds. Source it: `source scripts/wsl/env.sh`
export PATH="$HOME/.cargo/bin:$PATH"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$HOME/android-ndk-r27d}"
# Keep build artefacts on the Linux filesystem (much faster than /mnt/<drive>).
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/keyvora-target}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export REPO_ROOT
