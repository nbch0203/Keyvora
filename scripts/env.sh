#!/usr/bin/env bash
# Source this file (Git Bash) to put the per-user toolchains on PATH:
#   source scripts/env.sh
# Paths match docs/BUILD.md §1. Override any variable before sourcing if your layout differs.
_win2posix() { cygpath -u "$1" 2>/dev/null || echo "$1"; }
_LOCAL="$(_win2posix "${LOCALAPPDATA:-$HOME/AppData/Local}")"
export CARGO_HOME="${CARGO_HOME:-$(_win2posix "$USERPROFILE")/.cargo}"
export JAVA_HOME="${JAVA_HOME:-$_LOCAL/Programs/jdk-17}"
export GRADLE_HOME="${GRADLE_HOME:-$_LOCAL/Programs/gradle-8.13}"
export ANDROID_HOME="${ANDROID_HOME:-$_LOCAL/Android/Sdk}"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/27.3.13750724}"
export PATH="$CARGO_HOME/bin:$JAVA_HOME/bin:$GRADLE_HOME/bin:$ANDROID_HOME/platform-tools:$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"
