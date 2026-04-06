# Build libbibavpn_jni.so for all Android ABIs into android/app/src/main/jniLibs.
# Prerequisites: Rust toolchains, `cargo install cargo-ndk`, ANDROID_NDK_HOME, and:
#   rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86 -t x86_64 `
    -o android/app/src/main/jniLibs `
    build -p bibavpn-jni --release
