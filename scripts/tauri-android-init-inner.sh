#!/usr/bin/env bash
# Вызывается из docker/Dockerfile.tauri-android-init (контейнер: /work = корень biba-vpn).
set -euo pipefail
export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-17-openjdk-amd64}"
export CI=1
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec bash "$ROOT/scripts/tauri-android-init-local.sh"
