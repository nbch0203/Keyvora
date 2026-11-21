#!/usr/bin/env bash
# Runs a repo script inside WSL Ubuntu from Git Bash on Windows (needed because Smart App Control blocks
# locally compiled Rust binaries on the Windows host). Example: scripts/wsl.sh scripts/wsl/test-core.sh
# Each argument reaches Linux unchanged as its own argv entry, never re-parsed by a shell: `--exec` skips the
# default shell that `wsl.exe --` hands a joined command line to, and MSYS path conversion is turned off so an
# argument such as /tmp/x is not rewritten to a Windows path.
set -euo pipefail
DISTRO="${WSL_DISTRO:-Ubuntu}"
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
REPO_WIN="$(cd "$(dirname "$0")/.." && pwd -W 2>/dev/null || pwd)"
REPO_WSL="$(wsl.exe -d "$DISTRO" --exec wslpath -a "$REPO_WIN" | tr -d '\r')"
exec wsl.exe -d "$DISTRO" --exec bash -lc 'cd "$1" && shift && exec bash "$@"' wsl.sh "$REPO_WSL" "$@"
