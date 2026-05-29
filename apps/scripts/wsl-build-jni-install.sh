#!/usr/bin/env bash
set -euo pipefail
export PATH="${HOME}/.cargo/bin:${PATH}"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
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
rustup target add aarch64-linux-android armv7-linux-androideabi 2>/dev/null || true
if ! cargo ndk --version >/dev/null 2>&1; then
  echo "Installing cargo-ndk..."
  cargo install cargo-ndk --locked
fi

echo "Build Tauri Android APK..."
bash "$REPO_ROOT/apps/scripts/build-android-apk-wsl.sh"

echo "Install Tauri Android APK via Windows adb..."
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
  WIN_APK="${WIN_REPO}\\apps\\bibavpn-desktop\\src-tauri\\gen\\android\\app\\build\\outputs\\apk\\universal\\debug\\app-universal-debug.apk"
  cmd.exe /c "\"$ADB_WIN\" install -r \"$WIN_APK\""
else
  APK="$REPO_ROOT/apps/bibavpn-desktop/src-tauri/gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk"
  adb install -r "$APK"
fi

if [[ -x "$ADB_WIN" ]]; then
  echo "adb:"
  "$ADB_WIN" devices
fi
echo "Done."
