#!/usr/bin/env bash
# Подключить в ~/.bashrc: source /path/to/biba-vpn/scripts/wsl-android-env.sh
# Или выполнить перед сборкой Android.
export ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/26.1.10909125}"
NDK_LLVM_BIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
export PATH="$NDK_LLVM_BIN:$PATH:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools"
# Иначе rustc на финальном линке вызывает хостовый `cc` и падает.
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$NDK_LLVM_BIN/aarch64-linux-android29-clang"
export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="$NDK_LLVM_BIN/armv7a-linux-androideabi29-clang"
export CARGO_TARGET_I686_LINUX_ANDROID_LINKER="$NDK_LLVM_BIN/i686-linux-android29-clang"
export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$NDK_LLVM_BIN/x86_64-linux-android29-clang"
export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-17-openjdk-amd64}"
# Артефакты на ext4 (не на DrvFS). Не делайте `rm -rf` этого каталога без нужды — следующая
# сборка заново компилирует все зависимости и выглядит как «зависание» (десятки минут).
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/biba-vpn-cargo-target}"
