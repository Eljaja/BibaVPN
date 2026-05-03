#!/usr/bin/env bash
# Одноразовая установка Android SDK + NDK в $HOME/Android/Sdk (WSL/Linux).
set -euo pipefail
ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
mkdir -p "$ANDROID_HOME/cmdline-tools"
if [ ! -d "$ANDROID_HOME/cmdline-tools/latest" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  cd "$tmp"
  curl -fsSO https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip
  unzip -qo commandlinetools-linux-11076708_latest.zip -d "$ANDROID_HOME/cmdline-tools"
  mv "$ANDROID_HOME/cmdline-tools/cmdline-tools" "$ANDROID_HOME/cmdline-tools/latest"
fi
export PATH="$PATH:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools"
set +o pipefail
yes 2>/dev/null | sdkmanager --sdk_root="$ANDROID_HOME" --licenses >/dev/null || true
set -o pipefail
sdkmanager --sdk_root="$ANDROID_HOME" \
  "platform-tools" \
  "platforms;android-34" \
  "build-tools;34.0.0" \
  "ndk;26.1.10909125"
echo "ANDROID_HOME=$ANDROID_HOME"
ls "$ANDROID_HOME/ndk"
