#!/usr/bin/env bash
# Runs a repo script inside WSL Ubuntu from Git Bash on Windows (needed because Smart App Control blocks
# locally compiled Rust binaries on the Windows host). Example: scripts/wsl.sh scripts/wsl/test-core.sh
set -euo pipefail
REPO_WIN="$(cd "$(dirname "$0")/.." && pwd -W 2>/dev/null || pwd)"
REPO_WSL="$(wsl.exe -d "${WSL_DISTRO:-Ubuntu}" -- wslpath -a "$REPO_WIN" | tr -d '\r')"
exec wsl.exe -d "${WSL_DISTRO:-Ubuntu}" -- bash -lc "cd '$REPO_WSL' && bash $*"
