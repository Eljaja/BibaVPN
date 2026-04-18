#!/usr/bin/env bash
# Full WSL build: Rust, libbibavpn_jni.so (all ABIs), debug APK.
# Run from WSL:  cd /mnt/c/Users/ilya/biba-vpn/biba-vpn   && bash scripts/wsl-build-all.sh
# Requires: network, ~8 GB disk for SDK/NDK on first run.

set -eu
export PATH="$HOME/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
[[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-17-openjdk-amd64}"
export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$HOME/android-sdk}"
export ANDROID_NDK_ROOT="${ANDROID_NDK_ROOT:-}"
NDK_VERSION="26.3.11579264"

need_cmd() { command -v "$1" >/dev/null 2>&1; }

if ! need_cmd java; then
  echo "Install JDK 17, e.g.: sudo apt-get install -y openjdk-17-jdk"
  exit 1
fi

if ! need_cmd unzip || ! need_cmd wget; then
  sudo apt-get install -y unzip wget ca-certificates || true
fi

SM="$ANDROID_SDK_ROOT/cmdline-tools/latest/bin/sdkmanager"
if [[ ! -x "$SM" ]]; then
  echo "Installing Android cmdline-tools to $ANDROID_SDK_ROOT ..."
  mkdir -p "$ANDROID_SDK_ROOT/cmdline-tools"
  TMP="$(mktemp -d)"
  cd "$TMP"
  wget -q https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip -O cmdline.zip \
    || wget -q https://dl.google.com/android/repository/commandlinetools-linux-10406996_latest.zip -O cmdline.zip
  unzip -q cmdline.zip
  rm -rf "$ANDROID_SDK_ROOT/cmdline-tools/latest"
  mv cmdline-tools "$ANDROID_SDK_ROOT/cmdline-tools/latest"
  cd "$REPO_ROOT"
  rm -rf "$TMP"
fi

echo "SDK: accepting licenses and installing platform-tools, API 34, build-tools, NDK ..."
yes | "$SM" --sdk_root="$ANDROID_SDK_ROOT" --licenses 2>/dev/null || true
"$SM" --sdk_root="$ANDROID_SDK_ROOT" \
  "platform-tools" \
  "platforms;android-34" \
  "build-tools;34.0.0" \
  "ndk;$NDK_VERSION"

export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ANDROID_SDK_ROOT/ndk/$NDK_VERSION}"
if [[ ! -d "$ANDROID_NDK_HOME" ]]; then
  echo "NDK not found: $ANDROID_NDK_HOME"
  ls -la "$ANDROID_SDK_ROOT/ndk" || true
  exit 1
fi

echo "Rust + libbibavpn_jni + Gradle (see scripts/wsl-build-rust-apk.sh, no cargo-ndk) ..."
bash "$SCRIPT_DIR/wsl-build-rust-apk.sh"
