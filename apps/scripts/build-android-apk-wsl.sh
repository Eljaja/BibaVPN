#!/usr/bin/env bash
# Сборка installable debug APK из WSL (обход отсутствия MSVC link.exe на Windows для build.rs хоста).
# Перед первой сборкой: apps/scripts/dl-ndk-wsl.sh и apps/scripts/patch-windows-ndk-linux-prebuilt-for-wsl.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export ANDROID_HOME="${ANDROID_HOME:-/mnt/c/Users/ilya/AppData/Local/Android/Sdk}"
unset ANDROID_NDK_HOME NDK_HOME ANDROID_NDK_ROOT 2>/dev/null || true
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/26.3.11579264}"
export NDK_HOME="$ANDROID_NDK_HOME"
export ANDROID_NDK_ROOT="$ANDROID_NDK_HOME"
echo "ANDROID_NDK_HOME=$ANDROID_NDK_HOME"
export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-17-openjdk-amd64}"
export PATH="${HOME}/.cargo/bin:${JAVA_HOME}/bin:${PATH}"

if [ ! -d "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64" ]; then
  echo "Нет linux-x86_64 в NDK. Выполните из WSL:" >&2
  echo "  bash apps/scripts/dl-ndk-wsl.sh" >&2
  echo "  bash apps/scripts/patch-windows-ndk-linux-prebuilt-for-wsl.sh" >&2
  exit 1
fi

rustup target add aarch64-linux-android armv7-linux-androideabi 2>/dev/null || true

cd "$ROOT/apps/bibavpn-desktop"
npm install
npm install --prefix ./ui
npm run android:bootstrap

LP="$ROOT/apps/bibavpn-desktop/src-tauri/gen/android/local.properties"
mkdir -p "$(dirname "$LP")"
{
  echo "sdk.dir=$ANDROID_HOME"
  echo "ndk.dir=$ANDROID_NDK_HOME"
} >"$LP"

bash "$ROOT/apps/scripts/wsl-build-tauri-android-jni.sh"
npm run build --prefix ./ui
exec npx tauri android build --debug --ci --apk
