#!/bin/bash
# Cross-compiles the Windows binaries (works from macOS, Linux or Windows Git Bash).
# Output: dist/ClaudeGuard-windows-{amd64,arm64}.zip
set -euo pipefail
cd "$(dirname "$0")"

rm -rf dist
for arch in amd64 arm64; do
  out="dist/ClaudeGuard-windows-$arch"
  mkdir -p "$out"
  GOOS=windows GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" \
    -o "$out/claudeguard.exe" ./cmd/claudeguard
  GOOS=windows GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -H windowsgui" \
    -o "$out/ClaudeGuardTray.exe" ./cmd/ClaudeGuardTray
  cp install.cmd uninstall.cmd README.md "$out/"
  (cd dist && zip -qr "ClaudeGuard-windows-$arch.zip" "ClaudeGuard-windows-$arch")
done
ls -lh dist/*.zip
