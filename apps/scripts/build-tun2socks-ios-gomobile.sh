#!/usr/bin/env bash
# Build tun2socks (xjasonlyu/tun2socks) for iOS via gomobile → XCFramework.
# Requires: Go, gomobile, Xcode CLI tools (macOS only).
# Run from repo root:
#   bash apps/scripts/build-tun2socks-ios-gomobile.sh
#
# Output: apps/bibavpn-desktop/src-tauri/ios-bibavpn-extras/Frameworks/Tun2socks.xcframework
set -euo pipefail
export PATH="$HOME/go/bin:$HOME/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT_DIR="$ROOT/apps/bibavpn-desktop/src-tauri/ios-bibavpn-extras/Frameworks"
# Post-iOS-fd-offset fixes live on main; pin explicitly if needed for reproducibility.
TUN2SOCKS_TAG="${TUN2SOCKS_TAG:-v2.6.0}"

command -v go >/dev/null 2>&1 || {
  echo "Go is required" >&2
  exit 1
}

command -v xcodebuild >/dev/null 2>&1 || {
  echo "Xcode / xcodebuild is required (run on macOS)" >&2
  exit 1
}

command -v gomobile >/dev/null 2>&1 || {
  echo "Installing gomobile..."
  go install golang.org/x/mobile/cmd/gomobile@latest
  go install golang.org/x/mobile/cmd/gobind@latest
}
gomobile init

BUILD_ROOT="$(mktemp -d)"
cleanup() { rm -rf "$BUILD_ROOT"; }
trap cleanup EXIT

cd "$BUILD_ROOT"
git clone --depth 1 --branch "$TUN2SOCKS_TAG" https://github.com/xjasonlyu/tun2socks.git \
  || git clone --depth 1 https://github.com/xjasonlyu/tun2socks.git

cd tun2socks

mkdir -p "$OUT_DIR"

gomobile bind -v \
  -target=ios \
  -o "$OUT_DIR/Tun2socks.xcframework" \
  ./engine

echo "OK: $OUT_DIR/Tun2socks.xcframework"
ls -la "$OUT_DIR/Tun2socks.xcframework"
