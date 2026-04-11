#!/usr/bin/env bash
# Rust + JNI (.so для всех ABI) + Gradle debug APK. Обход cargo-ndk (на некоторых WSL даёт SIGBUS).
set -eu
export PATH="$HOME/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
[[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-17-openjdk-amd64}"
export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$HOME/android-sdk}"
NDK_VERSION="${NDK_VERSION:-26.3.11579264}"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ANDROID_SDK_ROOT/ndk/$NDK_VERSION}"
export ANDROID_HOME="$ANDROID_SDK_ROOT"

TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64"
API="${ANDROID_API_LEVEL:-24}"
if [[ ! -x "$TOOLCHAIN/bin/aarch64-linux-android${API}-clang" ]]; then
  echo "Нет clang $TOOLCHAIN/bin/aarch64-linux-android${API}-clang; попробуйте API 21 или 34."
  ls "$TOOLCHAIN/bin" | grep -E 'aarch64-linux-android[0-9]+-clang' | head -5 || true
  exit 1
fi

export CC_aarch64_linux_android="$TOOLCHAIN/bin/aarch64-linux-android${API}-clang"
export CXX_aarch64_linux_android="$TOOLCHAIN/bin/aarch64-linux-android${API}-clang++"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CC_aarch64_linux_android"
export AR_aarch64_linux_android="$TOOLCHAIN/bin/llvm-ar"

export CC_armv7_linux_androideabi="$TOOLCHAIN/bin/armv7a-linux-androideabi${API}-clang"
export CXX_armv7_linux_androideabi="$TOOLCHAIN/bin/armv7a-linux-androideabi${API}-clang++"
export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="$CC_armv7_linux_androideabi"
export AR_armv7_linux_androideabi="$TOOLCHAIN/bin/llvm-ar"

export CC_i686_linux_android="$TOOLCHAIN/bin/i686-linux-android${API}-clang"
export CARGO_TARGET_I686_LINUX_ANDROID_LINKER="$CC_i686_linux_android"
export AR_i686_linux_android="$TOOLCHAIN/bin/llvm-ar"

export CC_x86_64_linux_android="$TOOLCHAIN/bin/x86_64-linux-android${API}-clang"
export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$CC_x86_64_linux_android"
export AR_x86_64_linux_android="$TOOLCHAIN/bin/llvm-ar"

rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android

echo "Сборка bibavpn (release) ..."
cargo build -p bibavpn --release

echo "tun2socks AAR (gomobile, 16 KB ELF) ..."
if command -v go >/dev/null 2>&1; then
  bash "$SCRIPT_DIR/build-tun2socks-gomobile.sh" || echo "Предупреждение: не удалось собрать tun2socks.aar"
else
  echo "Пропуск: нет Go — положите android/app/libs/tun2socks.aar (см. scripts/build-tun2socks-gomobile.sh) или Gradle возьмёт Maven AAR без 16 KB."
fi

echo "Сборка libbibavpn_jni.so (4 ABI) ..."
OUT="$REPO_ROOT/android/app/src/main/jniLibs"
mkdir -p "$OUT/arm64-v8a" "$OUT/armeabi-v7a" "$OUT/x86" "$OUT/x86_64"

cargo build -p bibavpn-jni --release --target aarch64-linux-android
cp -f "$REPO_ROOT/target/aarch64-linux-android/release/libbibavpn_jni.so" "$OUT/arm64-v8a/"

cargo build -p bibavpn-jni --release --target armv7-linux-androideabi
cp -f "$REPO_ROOT/target/armv7-linux-androideabi/release/libbibavpn_jni.so" "$OUT/armeabi-v7a/"

cargo build -p bibavpn-jni --release --target i686-linux-android
cp -f "$REPO_ROOT/target/i686-linux-android/release/libbibavpn_jni.so" "$OUT/x86/"

cargo build -p bibavpn-jni --release --target x86_64-linux-android
cp -f "$REPO_ROOT/target/x86_64-linux-android/release/libbibavpn_jni.so" "$OUT/x86_64/"

echo "Gradle: wrapper + assembleDebug ..."
GRADLE_VER="8.7"
GR_ZIP="/tmp/gradle-${GRADLE_VER}-bin.zip"
if [[ ! -d "/tmp/gradle-${GRADLE_VER}" ]]; then
  wget -q "https://services.gradle.org/distributions/gradle-${GRADLE_VER}-bin.zip" -O "$GR_ZIP"
  unzip -q -o "$GR_ZIP" -d /tmp
fi
GR_BIN="/tmp/gradle-${GRADLE_VER}/bin/gradle"
cd "$REPO_ROOT/android"
echo "sdk.dir=$ANDROID_SDK_ROOT" > local.properties
if [[ ! -f gradlew ]]; then
  "$GR_BIN" wrapper --gradle-version "$GRADLE_VER" --distribution-type bin
fi
chmod +x gradlew 2>/dev/null || true
./gradlew assembleDebug --no-daemon

APK="$REPO_ROOT/android/app/build/outputs/apk/debug/app-debug.apk"
ls -la "$APK"
echo "OK: $APK"
