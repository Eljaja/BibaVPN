#!/usr/bin/env bash
# Локальный `tauri android init --ci` (WSL 22.04 / Linux с Android SDK, без Docker).
# Нужно: Node, npm, Rust, JDK 17+, ANDROID_HOME (как у Android Studio).
# Запуск из корня репозитория biba-vpn:
#   bash apps/scripts/tauri-android-init-local.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export CI="${CI:-1}"

if [ -z "${JAVA_HOME:-}" ]; then
  for j in /usr/lib/jvm/java-17-openjdk-amd64 /usr/lib/jvm/java-21-openjdk-amd64; do
    if [ -d "$j" ]; then
      export JAVA_HOME="$j"
      break
    fi
  done
fi
if [ -z "${JAVA_HOME:-}" ] || [ ! -d "$JAVA_HOME" ]; then
  echo "Установите JDK (например apt install openjdk-17-jdk) и при необходимости задайте JAVA_HOME." >&2
  exit 1
fi

if [ -z "${ANDROID_HOME:-}" ] && [ -n "${ANDROID_SDK_ROOT:-}" ]; then
  export ANDROID_HOME="$ANDROID_SDK_ROOT"
fi
if [ -z "${ANDROID_HOME:-}" ] || [ ! -d "$ANDROID_HOME" ]; then
  echo "Задайте ANDROID_HOME на каталог Android SDK (например ~/Android/Sdk)." >&2
  exit 1
fi

DESK="$ROOT/apps/bibavpn-desktop"
if [ ! -f "$DESK/package.json" ]; then
  echo "Нет $DESK/package.json" >&2
  exit 1
fi

cd "$DESK"
npm install
exec npx tauri android init --ci
