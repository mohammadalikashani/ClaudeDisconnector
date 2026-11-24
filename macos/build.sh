#!/bin/bash
# Builds build/ClaudeGuard.app and build/claudeguardd (no root needed).
set -euo pipefail
cd "$(dirname "$0")"

swift build -c release
BIN="$(swift build -c release --show-bin-path)"

rm -rf build
mkdir -p build/ClaudeGuard.app/Contents/MacOS
cp Resources/Info.plist build/ClaudeGuard.app/Contents/Info.plist
cp "$BIN/ClaudeGuard" build/ClaudeGuard.app/Contents/MacOS/ClaudeGuard
cp "$BIN/claudeguardd" build/claudeguardd

codesign --force --sign - build/ClaudeGuard.app >/dev/null
codesign --force --sign - build/claudeguardd >/dev/null
echo "Built: $(pwd)/build/ClaudeGuard.app and $(pwd)/build/claudeguardd"
