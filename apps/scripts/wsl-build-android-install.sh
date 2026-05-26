#!/usr/bin/env bash
# Build BibaVPN Android APK in WSL and install (adb) when device is connected.
# Run:  wsl -e bash /mnt/c/Users/.../biba-vpn/apps/scripts/wsl-build-android-install.sh
set -euo pipefail
SRC="/mnt/c/Users/ilya/biba-vpn/biba-vpn"
DST="/root/biba-vpn"
export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-17-openjdk-amd64}"
export ANDROID_HOME="${ANDROID_HOME:-/root/Android/Sdk}"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export NDK_HOME="${NDK_HOME:-$ANDROID_HOME/ndk/26.1.10909125}"
export PATH="$HOME/.cargo/bin:$ANDROID_HOME/platform-tools:$ANDROID_HOME/cmdline-tools/latest/bin:/usr/local/bin:/usr/bin:$PATH"
export CARGO_TERM_COLOR=always

if [ ! -d "$SRC/apps/bibavpn-desktop" ]; then
  echo "No apps/bibavpn-desktop at $SRC" >&2
  exit 1
fi

mkdir -p /root
rsync -a --delete \
  --exclude=node_modules \
  --exclude=target \
  --exclude=ui/node_modules \
  --exclude=ui/dist \
  "$SRC/" "$DST/"

cd "$DST"
bash apps/scripts/build-android-apk-wsl.sh

# APK path from Tauri. Prefer signed debug APKs for sideload/ADB; unsigned release
# artifacts are not installable on Android TV.
APK=""
for p in \
  "apps/bibavpn-desktop/src-tauri/gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk" \
  "apps/bibavpn-desktop/src-tauri/gen/android/app/build/outputs/apk/arm64/debug/app-arm64-debug.apk" \
  "apps/bibavpn-desktop/src-tauri/gen/android/app/build/outputs/apk/arm64-v8a/debug/app-arm64-v8a-debug.apk" \
  "apps/bibavpn-desktop/src-tauri/gen/android/app/build/outputs/apk/debug/app-debug.apk"
 do
  if [ -f "$p" ]; then
    APK="$p"
    break
  fi
done
if [ -z "$APK" ]; then
  echo "APK not found, listing outputs:" >&2
  find apps/bibavpn-desktop/src-tauri/gen/android -name "*.apk" 2>/dev/null | head -20
  exit 1
fi

echo "Built: $APK"

if command -v adb >/dev/null 2>&1; then
  adb start-server
  if adb devices | grep -q "device$"; then
    # aligned/universal APK: usually install with -r
    adb install -r "$APK" && echo "Installed on device."
  else
    echo "No device in 'adb devices'. APK: $PWD/$APK" >&2
  fi
else
  echo "adb not in PATH ($ANDROID_HOME/platform-tools). APK: $PWD/$APK" >&2
fi
