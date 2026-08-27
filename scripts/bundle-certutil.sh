#!/usr/bin/env bash
# Copies certutil + its NSS/NSPR dylibs into the app Resources, rewrites their load
# paths to @loader_path so the app is self-contained, and re-signs everything.
set -euo pipefail
SRC_CERTUTIL="${1:-/opt/homebrew/opt/nss/bin/certutil}"
NSSLIB="$(cd "$(dirname "$SRC_CERTUTIL")/../lib" && pwd)"
DEST="App/CheburcertApp/Resources"
mkdir -p "$DEST"
cp "$SRC_CERTUTIL" "$DEST/certutil"
chmod u+w "$DEST/certutil"

# Copy every non-system dylib the binary (transitively) LINKS against.
copy_deps() {
  local bin="$1"
  otool -L "$bin" | awk 'NR>1{print $1}' | while read -r lib; do
    case "$lib" in
      /usr/lib/*|/System/*) continue;;
      @loader_path/*|@rpath/*|@executable_path/*) continue;;
    esac
    local base; base="$(basename "$lib")"
    if [ ! -f "$DEST/$base" ]; then
      cp "$lib" "$DEST/$base"
      chmod u+w "$DEST/$base"
      install_name_tool -id "@loader_path/$base" "$DEST/$base" || true
      copy_deps "$DEST/$base"
    fi
    install_name_tool -change "$lib" "@loader_path/$base" "$bin" || true
  done
}
copy_deps "$DEST/certutil"

# certutil dlopen()s the NSS PKCS#11 softoken modules at runtime to open a cert DB —
# these are NOT in `otool -L`, so copy them explicitly (plus their linked deps).
for m in libsoftokn3.dylib libfreebl3.dylib; do
  cp "$NSSLIB/$m" "$DEST/$m"
  chmod u+w "$DEST/$m"
  install_name_tool -id "@loader_path/$m" "$DEST/$m" || true
  copy_deps "$DEST/$m"
done

# install_name_tool invalidates each binary's code signature. On Apple Silicon a
# signed, hardened app that spawns a binary with a broken signature has it killed
# with SIGKILL (surfaces as certutil exit code 9). Re-sign everything ad-hoc so the
# signatures are valid; the app signing later just seals these into its CodeResources.
echo "Re-signing bundled binaries (ad-hoc)…"
for f in "$DEST"/*.dylib "$DEST/certutil"; do
  codesign --remove-signature "$f" 2>/dev/null || true
  codesign --force --sign - "$f"
done

echo "Bundled into $DEST:"
ls "$DEST"
codesign -v "$DEST/certutil" && echo "certutil signature OK"