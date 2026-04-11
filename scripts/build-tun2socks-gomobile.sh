#!/usr/bin/env bash
# Сборка tun2socks (gomobile) с ELF 16 KB для libgojni.so — см. developer.android.com/guide/practices/page-sizes
set -eu
export PATH="$HOME/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
[[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$REPO_ROOT/android/app/libs"
TUN2SOCKS_TAG="${TUN2SOCKS_TAG:-v2.6.0}"
NDK_VERSION="${NDK_VERSION:-26.3.11579264}"
export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$HOME/android-sdk}"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ANDROID_SDK_ROOT/ndk/$NDK_VERSION}"
export ANDROID_HOME="$ANDROID_SDK_ROOT"

command -v go >/dev/null 2>&1 || { echo "Нужен Go (go install ...)"; exit 1; }
command -v gomobile >/dev/null 2>&1 || {
  echo "Установка gomobile..."
  go install golang.org/x/mobile/cmd/gomobile@latest
  go install golang.org/x/mobile/cmd/gobind@latest
}
gomobile init

BUILD_ROOT="$(mktemp -d)"
cleanup() { rm -rf "$BUILD_ROOT"; }
trap cleanup EXIT

cd "$BUILD_ROOT"
git clone --depth 1 --branch "$TUN2SOCKS_TAG" https://github.com/xjasonlyu/tun2socks.git
cd tun2socks

export CGO_LDFLAGS="-Wl,-z,max-page-size=16384"
# Все ABI, как в приложении (minSdk 29, API 24 достаточно для gomobile).
gomobile bind -v \
  -target=android/arm,android/arm64,android/386,android/amd64 \
  -androidapi 24 \
  -o tun2socks.aar \
  ./engine

mkdir -p "$OUT_DIR"
cp -f tun2socks.aar "$OUT_DIR/tun2socks.aar"
ls -la "$OUT_DIR/tun2socks.aar"
echo "OK: $OUT_DIR/tun2socks.aar"
