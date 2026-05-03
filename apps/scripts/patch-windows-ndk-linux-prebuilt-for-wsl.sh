#!/usr/bin/env bash
# Добавляет toolchains/llvm/prebuilt/linux-x86_64 в Windows-NDK (рядом с windows-x86_64),
# чтобы cargo/tauri под WSL находили нужный toolchain по стандартному ANDROID_HOME/ndk/...
set -euo pipefail
WIN_NDK="/mnt/c/Users/ilya/AppData/Local/Android/Sdk/ndk/26.3.11579264"
LINUX_NDK="/mnt/c/Users/ilya/biba-vpn-ndk/android-ndk-r26c"
SRC="$LINUX_NDK/toolchains/llvm/prebuilt/linux-x86_64"
DST="$WIN_NDK/toolchains/llvm/prebuilt/linux-x86_64"
if [ ! -d "$SRC" ]; then
  echo "Нет $SRC — сначала apps/scripts/dl-ndk-wsl.sh" >&2
  exit 1
fi
mkdir -p "$DST"
rsync -a "$SRC/" "$DST/"
echo "OK: $DST"
