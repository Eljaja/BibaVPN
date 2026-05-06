#!/usr/bin/env bash
# After `tauri ios init`: copies VPN extras + ffi header into gen/apple and merges XcodeGen project.yml.
# Run from repo root:
#   bash apps/scripts/integrate-bibavpn-into-tauri-ios.sh
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
GEN="$ROOT/apps/bibavpn-desktop/src-tauri/gen/apple"
EXTRAS="$ROOT/apps/bibavpn-desktop/src-tauri/ios-bibavpn-extras"
HDR_SRC="$ROOT/apps/bibavpn-ffi/include/bibavpn_ffi.h"

if [ ! -f "$GEN/project.yml" ]; then
  echo "Нет $GEN/project.yml — сначала: cd apps/bibavpn-desktop && npm run tauri ios init" >&2
  exit 1
fi

mkdir -p "$GEN/BibaVpnTunnel/include"
cp -f "$HDR_SRC" "$GEN/BibaVpnTunnel/include/bibavpn_ffi.h"
cp -f "$EXTRAS/BibaVpnTunnel/BibaVpnTunnel-Bridging-Header.h" "$GEN/BibaVpnTunnel/"
cp -f "$EXTRAS/BibaVpnTunnel/PacketTunnelProvider.swift" "$GEN/BibaVpnTunnel/"
cp -f "$EXTRAS/BibaVpnTunnel/Info.plist" "$GEN/BibaVpnTunnel/"
cp -f "$EXTRAS/BibaVpnTunnel/BibaVpnTunnel.entitlements" "$GEN/BibaVpnTunnel/"
mkdir -p "$GEN/BibaVpnTunnel/rust-static"
cp -f "$EXTRAS/BibaVpnTunnel/rust-static/README.md" "$GEN/BibaVpnTunnel/rust-static/" 2>/dev/null || true

mkdir -p "$GEN/Sources"
cp -f "$EXTRAS/host-sources/BibaVpnAppleBridge.swift" "$GEN/Sources/"

if [ -d "$EXTRAS/Frameworks/Tun2socks.xcframework" ]; then
  mkdir -p "$GEN/Frameworks"
  rm -rf "$GEN/Frameworks/Tun2socks.xcframework"
  cp -R "$EXTRAS/Frameworks/Tun2socks.xcframework" "$GEN/Frameworks/"
fi

python3 "$SCRIPT_DIR/merge_bibavpn_ios_project.py" "$GEN"

if command -v xcodegen >/dev/null 2>&1; then
  (cd "$GEN" && xcodegen generate)
else
  echo "Подсказка: brew install xcodegen; затем в gen/apple выполните xcodegen generate перед сборкой Xcode." >&2
fi

echo "Готово. Соберите libbibavpn_ffi.a (см. ios-bibavpn-extras/BibaVpnTunnel/rust-static/README.md), затем Xcode build."
