#!/bin/bash
# Builds a universal (Apple Silicon + Intel) release zip with prebuilt binaries.
# Output: dist/ClaudeGuard-macos-universal.zip
# The zip's install.sh uses the included binaries, so users don't need Xcode tools.
set -euo pipefail
cd "$(dirname "$0")"

NAME=ClaudeGuard-macos-universal
OUT="dist/$NAME"
rm -rf dist
mkdir -p "$OUT/build/ClaudeGuard.app/Contents/MacOS" "$OUT/Resources"

bins=()
for arch in arm64 x86_64; do
  scratch=".build/pkg-$arch"
  swift build -c release --triple "$arch-apple-macosx13.0" --scratch-path "$scratch"
  bins+=("$(swift build -c release --triple "$arch-apple-macosx13.0" --scratch-path "$scratch" --show-bin-path)")
done

lipo -create -output "$OUT/build/claudeguardd" "${bins[0]}/claudeguardd" "${bins[1]}/claudeguardd"
lipo -create -output "$OUT/build/ClaudeGuard.app/Contents/MacOS/ClaudeGuard" \
  "${bins[0]}/ClaudeGuard" "${bins[1]}/ClaudeGuard"
cp Resources/Info.plist "$OUT/build/ClaudeGuard.app/Contents/Info.plist"

# Sign after lipo (lipo invalidates signatures). Ad-hoc only: not notarized.
codesign --force --sign - "$OUT/build/ClaudeGuard.app" >/dev/null
codesign --force --sign - "$OUT/build/claudeguardd" >/dev/null

cp Resources/com.claudeguard.daemon.plist "$OUT/Resources/"
cp install.sh uninstall.sh README.md "$OUT/"

(cd dist && ditto -c -k --keepParent "$NAME" "$NAME.zip")
lipo -archs "$OUT/build/claudeguardd"
ls -lh "dist/$NAME.zip"
