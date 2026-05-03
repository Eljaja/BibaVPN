#!/usr/bin/env bash
# Сборка release APK BibaVPN (Tauri Android) внутри образа bibavpn:tauri-android-init.
# из корня biba-vpn: docker run ... (см. deploy) или: bash apps/scripts/build-android-tauri-in-docker.sh
set -euo pipefail
export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-17-openjdk-amd64}"
# `tauri android init` wants CI; `tauri android build` rejects CI=1 (expects true/false).
export CI=true
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.cargo/bin:${PATH}"

# SDK из образа
export ANDROID_HOME="${ANDROID_HOME:-/opt/android-sdk}"
export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$ANDROID_HOME}"
if [[ -d "$ANDROID_HOME/ndk" ]]; then
  latest="$(ls -1 "$ANDROID_HOME/ndk" 2>/dev/null | sort -V | tail -1)"
  if [[ -n "${latest:-}" ]]; then
    export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/$latest"
  fi
fi

cd "$ROOT" && bash apps/scripts/tauri-android-init-local.sh
bash apps/scripts/integrate-bibavpn-into-tauri-android.sh
bash apps/scripts/wsl-build-tauri-android-jni.sh
cd "$ROOT/apps/bibavpn-desktop" && npm run build
npm run tauri:android:build
echo "APK (search):"
find "$ROOT/apps/bibavpn-desktop/src-tauri" -name '*.apk' 2>/dev/null | head -20
