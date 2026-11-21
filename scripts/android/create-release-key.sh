#!/usr/bin/env bash
# Creates the Android release signing key and apps/android/keystore.properties (both stay out of git).
# Run it yourself, in your own terminal: the password is typed here, never echoed, never put on a command line.
#
#   bash scripts/android/create-release-key.sh [ruta-del-keystore]     (default: ~/keyvora-release.jks)
#
# Afterwards back up the .jks and its password somewhere safe and offline: without them no update can be installed
# over the app, and whoever gets them can sign apps that Android treats as Keyvora.
set -euo pipefail
cd "$(dirname "$0")/../.."
source scripts/env.sh >/dev/null

KEYSTORE="${1:-$HOME/keyvora-release.jks}"
PROPS="${KEYVORA_KEYSTORE_PROPS:-apps/android/keystore.properties}"
ALIAS=keyvora

if [ -e "$KEYSTORE" ]; then echo "Ya existe $KEYSTORE: no se sobrescribe (borrarlo invalidaría las actualizaciones)."; exit 1; fi
if [ -e "$PROPS" ]; then echo "Ya existe $PROPS: no se sobrescribe."; exit 1; fi
case "$(cd "$(dirname "$KEYSTORE")" && pwd)/" in
  "$(pwd)/"*) echo "El keystore no puede estar dentro del repositorio."; exit 1 ;;
esac

read -rsp "Contraseña de la clave de firma (mínimo 12 caracteres): " P1; echo
read -rsp "Repítela: " P2; echo
if [ "$P1" != "$P2" ]; then echo "No coinciden."; exit 1; fi
if [ "${#P1}" -lt 12 ]; then echo "Demasiado corta."; exit 1; fi
unset P2
export KV_STOREPASS="$P1"
trap 'unset KV_STOREPASS P1' EXIT

# PKCS12 (keytool's default) uses one password for the store and the key.
keytool -genkeypair -keystore "$KEYSTORE" -storetype PKCS12 -alias "$ALIAS" -keyalg RSA -keysize 3072 \
  -validity 10000 -dname "CN=Keyvora" -storepass:env KV_STOREPASS -keypass:env KV_STOREPASS >/dev/null

# keystore.properties is read by apps/android/app/build.gradle.kts. Backslashes must be escaped in .properties.
escaped="${P1//\\/\\\\}"
store_path="$(cygpath -m "$KEYSTORE" 2>/dev/null || echo "$KEYSTORE")"
(
  umask 077
  printf 'storeFile=%s\nstorePassword=%s\nkeyAlias=%s\nkeyPassword=%s\n' "$store_path" "$escaped" "$ALIAS" "$escaped" > "$PROPS"
)
unset escaped
if [ "$PROPS" = "apps/android/keystore.properties" ] && ! git check-ignore -q "$PROPS"; then
  echo "AVISO: $PROPS no está ignorado por git. No lo subas."; exit 1
fi

echo
echo "Clave creada: $KEYSTORE (alias $ALIAS)"
echo "Configuración: $PROPS (ignorado por git)"
echo
echo "Huellas del certificado (la SHA-1 va en el cliente OAuth de Android; la SHA-256, en las notas de la release):"
keytool -list -v -keystore "$KEYSTORE" -alias "$ALIAS" -storepass:env KV_STOREPASS | grep -E "SHA1:|SHA256:"
echo
echo "Ahora haz copia de seguridad de $KEYSTORE y de su contraseña fuera de este ordenador."
