#!/usr/bin/env bash
# Сборка .ipa на macOS (локально или из CI).
# Требования: Xcode, CocoaPods (если попросит Tauri), Apple Developer, подпись в Xcode или переменные IOS_* / APPLE_API_* (см. https://v2.tauri.app/distribute/sign/ios/).
#
# Из корня репозитория:
#   bash apps/scripts/build-ios-ipa.sh
# Опции передаются в `tauri ios build`, например:
#   bash apps/scripts/build-ios-ipa.sh -- --export-method development
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DESKTOP="$ROOT/apps/bibavpn-desktop"
GEN_APPLE="$DESKTOP/src-tauri/gen/apple"
EXTRA_STATIC="$DESKTOP/src-tauri/ios-bibavpn-extras/BibaVpnTunnel/rust-static"

cd "$ROOT"

command -v xcodebuild >/dev/null 2>&1 || {
  echo "Нужен Xcode (macOS)." >&2
  exit 1
}

rustup target add aarch64-apple-ios 2>/dev/null || true

echo "== UI build"
(cd "$DESKTOP/ui" && npm install --no-audit --no-fund && npm run build)

echo "== bibavpn-ffi (device)"
cargo build -p bibavpn-ffi --release --target aarch64-apple-ios --locked

mkdir -p "$EXTRA_STATIC/Release-iphoneos" "$EXTRA_STATIC/Debug-iphoneos"
cp -f "$ROOT/target/aarch64-apple-ios/release/libbibavpn_ffi.a" "$EXTRA_STATIC/Release-iphoneos/"
cp -f "$ROOT/target/aarch64-apple-ios/release/libbibavpn_ffi.a" "$EXTRA_STATIC/Debug-iphoneos/"

echo "== Tauri iOS project"
(cd "$DESKTOP" && npm install --no-audit --no-fund)
if [[ ! -f "$GEN_APPLE/project.yml" ]]; then
  (cd "$DESKTOP" && npm exec -- tauri ios init --ci)
fi

bash "$ROOT/apps/scripts/integrate-bibavpn-into-tauri-ios.sh"

echo "== tauri ios build"
(cd "$DESKTOP" && npm exec -- tauri ios build "$@")

echo "== IPA search"
find "$GEN_APPLE" -name "*.ipa" -print 2>/dev/null || true
IPA="$(find "$GEN_APPLE" -name "*.ipa" 2>/dev/null | head -n1 || true)"
if [[ -n "${IPA:-}" ]]; then
  echo "Готово: $IPA"
else
  echo "Файл .ipa не найден под gen/apple — проверьте лог `tauri ios build` и подпись." >&2
  exit 1
fi
