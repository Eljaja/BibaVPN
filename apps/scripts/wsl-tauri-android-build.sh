#!/usr/bin/env bash
# Сборка Android в WSL (как однострочник ниже, но с определением каталога репо).
# Из Windows:  wsl -e bash /mnt/c/Users/ilya/biba-vpn/biba-vpn/apps/scripts/wsl-tauri-android-build.sh
# Из WSL:      bash apps/scripts/wsl-tauri-android-build.sh   (из корня biba-vpn)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export ANDROID_HOME="${ANDROID_HOME:-/root/Android/Sdk}"
export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$ANDROID_HOME}"
export NDK_HOME="${NDK_HOME:-$ANDROID_HOME/ndk/26.1.10909125}"
export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-17-openjdk-amd64}"
export PATH="$HOME/.cargo/bin:$ANDROID_HOME/platform-tools:$PATH"
cd "$ROOT/apps/bibavpn-desktop"
exec npm run tauri:android:build
