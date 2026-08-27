#!/usr/bin/env bash
# Build Release, codesign (Developer ID), notarize, staple, and produce a .dmg.
# Requires: DEVELOPER_ID_APP, NOTARY_PROFILE env vars.
set -euo pipefail
APP="build/obcert.app"
xcodebuild -project App/CheburcertApp/obcert.xcodeproj -scheme obcert \
  -configuration Release -derivedDataPath build/dd build
cp -R "build/dd/Build/Products/Release/obcert.app" "$APP"
codesign --force --deep --options runtime \
  --entitlements App/CheburcertApp/obcert.entitlements \
  --sign "$DEVELOPER_ID_APP" "$APP"
hdiutil create -volname obcert -srcfolder "$APP" -ov -format UDZO build/obcert.dmg
xcrun notarytool submit build/obcert.dmg --keychain-profile "$NOTARY_PROFILE" --wait
xcrun stapler staple build/obcert.dmg
echo "Made build/obcert.dmg"
