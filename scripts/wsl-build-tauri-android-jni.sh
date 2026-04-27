#!/usr/bin/env bash
# Собрать libbibavpn_jni.so для всех ABI в Tauri gen/android (после android:bootstrap).
# Запуск из корня репозитория biba-vpn:
#   bash scripts/wsl-build-tauri-android-jni.sh
set -euo pipefail
export PATH="${HOME}/.cargo/bin:${PATH}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/bibavpn-desktop/src-tauri/gen/android/app/src/main/jniLibs"

if [ ! -d "$ROOT/bibavpn-desktop/src-tauri/gen/android/app" ]; then
  echo "Нет gen/android — сначала: cd bibavpn-desktop && npm run android:bootstrap" >&2
  exit 1
fi

if [ -z "${ANDROID_NDK_HOME:-}" ] && [ -z "${NDK_HOME:-}" ] && [ -n "${ANDROID_HOME:-}" ]; then
  if [ -d "$ANDROID_HOME/ndk" ]; then
    latest="$(ls -1 "$ANDROID_HOME/ndk" 2>/dev/null | sort -V | tail -1)"
    if [ -n "${latest:-}" ]; then
      export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/$latest"
    fi
  fi
fi
if [ -z "${ANDROID_NDK_HOME:-}" ] && [ -n "${NDK_HOME:-}" ]; then
  export ANDROID_NDK_HOME="$NDK_HOME"
fi
if [ -z "${ANDROID_NDK_HOME:-}" ] || [ ! -d "$ANDROID_NDK_HOME" ]; then
  echo "Задайте ANDROID_NDK_HOME или установите NDK через sdkmanager (папка \$ANDROID_HOME/ndk/...)." >&2
  exit 1
fi

cd "$ROOT"
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android 2>/dev/null || true
if ! cargo ndk --version >/dev/null 2>&1; then
  echo "Установка cargo-ndk..."
  cargo install cargo-ndk --locked
fi

echo "Сборка bibavpn-jni → $OUT"
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86 -t x86_64 \
  -o "$OUT" \
  build -p bibavpn-jni --release
echo "Готово."
