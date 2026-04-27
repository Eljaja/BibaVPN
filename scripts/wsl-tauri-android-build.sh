#!/usr/bin/env bash
# Сборка APK/AAB из WSL (после android:bootstrap и wsl-build-tauri-android-jni.sh).
# Запуск из корня репозитория biba-vpn:
#   bash scripts/wsl-tauri-android-build.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=./wsl-android-env.sh
source "$ROOT/scripts/wsl-android-env.sh"

if [[ "$(pwd -P 2>/dev/null || pwd)" == /mnt/* ]]; then
  echo "Замечание: проект на /mnt/c/… — первая сборка может идти 15–40 мин (LLVM/ring/tauri)." >&2
  echo "Не удаляйте весь \$CARGO_TARGET_DIR без нужды — иначе всё пересоберётся с нуля." >&2
  echo "Надёжнее держать клон репозитория на ext4, например ~/src/biba-vpn." >&2
fi

cd "$ROOT/bibavpn-desktop"
exec npm run tauri:android:build
