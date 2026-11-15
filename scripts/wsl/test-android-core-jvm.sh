#!/usr/bin/env bash
# Runs the Android JVM unit tests on Linux with the real core loaded through JNA (CoreVectorsTest included),
# from a copy of apps/android on the Linux filesystem. Needs: JDK 17 (`sudo apt install -y openjdk-17-jdk-headless`).
# The Android SDK (cmdline-tools + platform 35 + build-tools 35) is installed per-user on first run.
set -euo pipefail
source "$(dirname "$0")/env.sh"
command -v javac >/dev/null || { echo "Missing JDK 17: sudo apt install -y openjdk-17-jdk-headless"; exit 1; }
SDK="$HOME/android-sdk"
if [ ! -x "$SDK/cmdline-tools/latest/bin/sdkmanager" ]; then
  tmp=$(mktemp -d)
  curl -sSfL -o "$tmp/clt.zip" https://dl.google.com/android/repository/commandlinetools-linux-13114758_latest.zip
  [ "$(sha1sum < "$tmp/clt.zip" | awk '{print $1}')" = "5fdcc763663eefb86a5b8879697aa6088b041e70" ] || { echo "checksum mismatch"; exit 1; }
  mkdir -p "$SDK/cmdline-tools" && unzip -q "$tmp/clt.zip" -d "$tmp" && mv "$tmp/cmdline-tools" "$SDK/cmdline-tools/latest" && rm -rf "$tmp"
  yes | "$SDK/cmdline-tools/latest/bin/sdkmanager" --sdk_root="$SDK" --licenses >/dev/null 2>&1 || true
  "$SDK/cmdline-tools/latest/bin/sdkmanager" --sdk_root="$SDK" "platforms;android-35" "build-tools;35.0.0" >/dev/null
fi
ROOT="$HOME/.cache/keyvora-android-jvm"
WORK="$ROOT/apps/android"
mkdir -p "$WORK" "$ROOT/packages/shared-models"
# Copy sources (not build outputs) to the Linux filesystem, keeping the repo layout (tests read ../../packages).
(cd "$REPO_ROOT/apps/android" && tar --exclude='./build' --exclude='./app/build' --exclude='./.gradle' --exclude='./local.properties' -cf - .) | (cd "$WORK" && tar -xf -)
rm -rf "$ROOT/packages/shared-models/test-vectors" && cp -r "$REPO_ROOT/packages/shared-models/test-vectors" "$ROOT/packages/shared-models/"
echo "sdk.dir=$SDK" > "$WORK/local.properties"
cd "$WORK"
chmod +x gradlew
./gradlew --no-daemon -q -Pkeyvora.requireHostCore=true :app:testDebugUnitTest "$@"
python3 - <<'EOF'
import glob, xml.etree.ElementTree as ET
t = f = e = s = 0
for p in glob.glob("app/build/test-results/testDebugUnitTest/*.xml"):
    r = ET.parse(p).getroot()
    t += int(r.get("tests")); f += int(r.get("failures")); e += int(r.get("errors")); s += int(r.get("skipped"))
    if "CoreVectors" in p:
        print("CoreVectorsTest:", r.get("tests"), "tests,", r.get("failures"), "failures,", r.get("skipped"), "skipped")
print(f"JVM tests={t} failures={f} errors={e} skipped={s}")
EOF
