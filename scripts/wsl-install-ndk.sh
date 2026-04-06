#!/usr/bin/env bash
set -eu
export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-17-openjdk-amd64}"
export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$HOME/android-sdk}"
SM="$ANDROID_SDK_ROOT/cmdline-tools/latest/bin/sdkmanager"
VER="${1:-26.3.11579264}"
rm -rf "$ANDROID_SDK_ROOT/ndk" "$ANDROID_SDK_ROOT/.temp" || true
"$SM" --sdk_root="$ANDROID_SDK_ROOT" "ndk;$VER"
