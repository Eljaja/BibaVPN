# Build libbibavpn_jni.so for all Android ABIs into Tauri gen/android.
# Run from repo root after android:bootstrap. Prerequisites: Rust toolchains,
#   rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $repoRoot
$out = "apps/bibavpn-desktop/src-tauri/gen/android/app/src/main/jniLibs"
if (-not (Test-Path "apps/bibavpn-desktop/src-tauri/gen/android/app")) {
    throw "Missing Tauri gen/android. Run: cd apps/bibavpn-desktop; npm run android:bootstrap"
}
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86 -t x86_64 `
    -o $out `
    build -p bibavpn-jni --release
