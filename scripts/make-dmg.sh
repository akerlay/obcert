#!/usr/bin/env bash
# Build Release, codesign (Developer ID), notarize, staple, and produce a .dmg.
# Requires: DEVELOPER_ID_APP, NOTARY_PROFILE env vars.
set -euo pipefail
APP="build/Cheburcert.app"
xcodebuild -project App/CheburcertApp/Cheburcert.xcodeproj -scheme Cheburcert \
  -configuration Release -derivedDataPath build/dd build
cp -R "build/dd/Build/Products/Release/Cheburcert.app" "$APP"
codesign --force --deep --options runtime \
  --entitlements App/CheburcertApp/Cheburcert.entitlements \
  --sign "$DEVELOPER_ID_APP" "$APP"
hdiutil create -volname Cheburcert -srcfolder "$APP" -ov -format UDZO build/Cheburcert.dmg
xcrun notarytool submit build/Cheburcert.dmg --keychain-profile "$NOTARY_PROFILE" --wait
xcrun stapler staple build/Cheburcert.dmg
echo "Made build/Cheburcert.dmg"
