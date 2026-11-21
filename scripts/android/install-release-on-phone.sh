#!/usr/bin/env bash
# Replaces a debug Keyvora on a phone by the signed release. The signing key changes, so Android requires
# uninstalling first, which DELETES the app's local data (vault, biometric key, settings). It only proceeds after you
# confirm that an encrypted copy was exported (Keyvora → Ajustes → Exportar copia cifrada) and kept outside the app.
#
#   bash scripts/android/install-release-on-phone.sh <serial-adb>      (adb devices -l lists it)
set -euo pipefail
cd "$(dirname "$0")/../.."
source scripts/env.sh >/dev/null

SERIAL="${1:?Uso: install-release-on-phone.sh <serial-adb>}"
APK="apps/android/app/build/outputs/apk/release/app-release.apk"
PKG="com.keyvora.app"
BT="$(ls -d "$ANDROID_HOME"/build-tools/* | tail -1)"
AAPT2="$BT/aapt2"; [ -x "$AAPT2" ] || AAPT2="$BT/aapt2.exe"
APKSIGNER="$BT/apksigner"; [ -x "$APKSIGNER" ] || APKSIGNER="$BT/apksigner.bat"

[ -f "$APK" ] || { echo "Falta $APK: compila antes con ./gradlew :app:assembleRelease (y keystore.properties)."; exit 1; }
if "$AAPT2" dump badging "$APK" | grep -q "application-debuggable"; then
  echo "$APK es debuggable: no es una release."; exit 1
fi
echo "APK a instalar (firma):"
"$APKSIGNER" verify --print-certs "$APK" | grep "SHA-256" || { echo "La APK no está firmada."; exit 1; }

adb -s "$SERIAL" get-state >/dev/null
echo
echo "Instalada ahora en $SERIAL:"
adb -s "$SERIAL" shell dumpsys package "$PKG" | grep -E "versionName|flags=\[" | head -2 || echo "  (no instalada)"
echo
echo "Desinstalar BORRA la bóveda guardada en el móvil. Antes, en Keyvora: Ajustes → Exportar copia cifrada,"
echo "y comprueba que el fichero está fuera de la app (Descargas, Drive, el ordenador…)."
read -rp "Si ya la exportaste, escribe EXPORTADA para continuar: " ok
[ "$ok" = "EXPORTADA" ] || { echo "Cancelado: no se ha tocado nada."; exit 1; }

adb -s "$SERIAL" uninstall "$PKG" >/dev/null 2>&1 || true
adb -s "$SERIAL" install "$APK"
adb -s "$SERIAL" shell settings put secure autofill_service "$PKG/.autofill.KeyvoraAutofillService"
echo
echo "Hecho. En el móvil: abre Keyvora → «Importar una copia cifrada» → elige el fichero exportado → contraseña maestra."
echo "Después vuelve a activar la biometría en Ajustes si la usabas."
