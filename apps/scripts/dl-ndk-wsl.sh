#!/usr/bin/env bash
set -euo pipefail
DEST="/mnt/c/Users/ilya/biba-vpn-ndk"
mkdir -p "$DEST"
cd "$DEST"
if [ -d android-ndk-r26c/toolchains/llvm/prebuilt/linux-x86_64 ]; then
  echo "NDK already unpacked at $DEST/android-ndk-r26c"
  exit 0
fi
if [ ! -f ndk-linux.zip ]; then
  wget -nv --show-progress -O ndk-linux.zip https://dl.google.com/android/repository/android-ndk-r26c-linux.zip
fi
unzip -qo ndk-linux.zip
rm -f ndk-linux.zip
ls android-ndk-r26c/toolchains/llvm/prebuilt/
