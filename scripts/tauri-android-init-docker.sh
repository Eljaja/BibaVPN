#!/usr/bin/env bash
# Собрать образ и выполнить `tauri android init --ci` (нужен Docker).
# Запуск из корня репозитория biba-vpn:
#   bash scripts/tauri-android-init-docker.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMG="${BIBAVPN_TAURI_INIT_IMAGE:-bibavpn:tauri-android-init}"
if ! docker image inspect "$IMG" &>/dev/null; then
  docker build --network=host -f docker/Dockerfile.tauri-android-init -t "$IMG" .
fi

exec docker run --rm --network=host \
  -v "$ROOT:/work" \
  -w /work \
  -e JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64 \
  "$IMG" \
  bash /work/scripts/tauri-android-init-inner.sh
