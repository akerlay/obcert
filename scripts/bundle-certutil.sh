#!/usr/bin/env bash
# Copies certutil + its NSS/NSPR dylibs into the app Resources and rewrites
# their load paths to @loader_path so the app is self-contained.
set -euo pipefail
SRC_CERTUTIL="${1:-/opt/homebrew/opt/nss/bin/certutil}"
DEST="App/CheburcertApp/Resources"
mkdir -p "$DEST"
cp "$SRC_CERTUTIL" "$DEST/certutil"
chmod u+w "$DEST/certutil"

# Copy every non-system dylib the binary (transitively) needs.
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
echo "Bundled certutil and deps into $DEST"
otool -L "$DEST/certutil"
