#!/usr/bin/env bash
set -euo pipefail
export PATH="${HOME}/.cargo/bin:${PATH}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NDK_VERSION="r26d"
NDK_DIR="${HOME}/android-ndk-${NDK_VERSION}"
NDK_ZIP="${HOME}/android-ndk-${NDK_VERSION}-linux.zip"
ADB_WIN="/mnt/c/Users/ilya/AppData/Local/Android/Sdk/platform-tools/adb.exe"

if [[ ! -d "$NDK_DIR" ]]; then
  echo "Downloading NDK ${NDK_VERSION}..."
  curl -fsSL -o "$NDK_ZIP" "https://dl.google.com/android/repository/android-ndk-${NDK_VERSION}-linux.zip"
  unzip -q "$NDK_ZIP" -d "$HOME"
  rm -f "$NDK_ZIP"
fi
export ANDROID_NDK_HOME="$NDK_DIR"
echo "ANDROID_NDK_HOME=$ANDROID_NDK_HOME"

cd "$REPO_ROOT"
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android 2>/dev/null || true
if ! cargo ndk --version >/dev/null 2>&1; then
  echo "Installing cargo-ndk..."
  cargo install cargo-ndk --locked
fi

echo "Building bibavpn-jni (release)..."
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86 -t x86_64 \
  -o android/app/src/main/jniLibs \
  build -p bibavpn-jni --release

echo "Gradle installDebug via Windows (JDK из Android Studio)..."
to_win_path() {
  local p="$1"
  if [[ "$p" =~ ^/mnt/([a-z])/(.+)$ ]]; then
    local d="${BASH_REMATCH[1]}"
    d=$(echo "$d" | tr '[:lower:]' '[:upper:]')
    local rest="${BASH_REMATCH[2]//\//\\}"
    echo "${d}:\\${rest}"
  else
    echo ""
  fi
}
if command -v wslpath >/dev/null 2>&1; then
  WIN_REPO="$(wslpath -w "$REPO_ROOT")"
else
  WIN_REPO="$(to_win_path "$REPO_ROOT")"
fi
if [[ -n "$WIN_REPO" ]]; then
  WIN_ANDROID="${WIN_REPO}\\android"
  # Одна пара кавычек для cmd — иначе «syntax incorrect»
  cmd.exe /c "cd /d \"$WIN_ANDROID\" && gradlew.bat installDebug"
else
  cd "$REPO_ROOT/android"
  ./gradlew installDebug
fi

if [[ -x "$ADB_WIN" ]]; then
  echo "adb:"
  "$ADB_WIN" devices
fi
echo "Done."
