#!/usr/bin/env bash
# После `tauri android init`: копирует VPN-слой из legacy android/ в gen/android.
# Запуск из корня репозитория biba-vpn:
#   bash scripts/integrate-bibavpn-into-tauri-android.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GEN="$ROOT/bibavpn-desktop/src-tauri/gen/android"
LEG="$ROOT/android/app/src/main"

if [ ! -d "$GEN/app" ]; then
  echo "Нет $GEN — сначала tauri android init" >&2
  exit 1
fi

APP_JAVA="$GEN/app/src/main/java/dev/bibavpn"
mkdir -p "$APP_JAVA/core"
for f in BibaVpnService.kt TauriVpnBridge.kt BibaApplication.kt AppLocale.kt; do
  cp -f "$LEG/java/dev/bibavpn/$f" "$APP_JAVA/"
done
cp -f "$LEG/java/dev/bibavpn/core/BibaNative.kt" "$APP_JAVA/core/"
cp -f "$LEG/java/dev/bibavpn/core/VpnProtect.kt" "$APP_JAVA/core/"

mkdir -p "$GEN/app/src/main/res/drawable"
cp -f "$LEG/res/drawable/ic_stat_vpn.xml" "$GEN/app/src/main/res/drawable/"

# Строки только для VPN-уведомлений (не перетираем strings Tauri)
EXR="$ROOT/bibavpn-desktop/src-tauri/android-bibavpn-extras/res"
mkdir -p "$GEN/app/src/main/res/values"
cp -f "$EXR/values/bibavpn_vpn_strings.xml" "$GEN/app/src/main/res/values/"

python3 "$ROOT/scripts/merge_bibavpn_manifest.py" "$GEN/app/src/main/AndroidManifest.xml"

# Зависимости tun2socks — отдельный фрагмент, подключается из app/build.gradle.kts
EXTRAS="$GEN/app/bibavpn-vpn-extras.gradle.kts"
cat > "$EXTRAS" << 'EOF'
dependencies {
    val tun2socksAar = file("${project.projectDir}/libs/tun2socks.aar")
    if (tun2socksAar.exists()) {
        implementation(files(tun2socksAar))
    } else {
        implementation("com.ooimi.library:tun2socks:1.0.4")
    }
    implementation("androidx.lifecycle:lifecycle-service:2.7.0")
}
EOF

BG="$GEN/app/build.gradle.kts"
if [ -f "$BG" ] && ! grep -q 'bibavpn-vpn-extras' "$BG"; then
  echo "" >> "$BG"
  echo '// BibaVPN native VPN + tun2socks' >> "$BG"
  echo 'apply(from = "bibavpn-vpn-extras.gradle.kts")' >> "$BG"
fi

mkdir -p "$GEN/app/libs"
if [ -f "$ROOT/android/app/libs/tun2socks.aar" ]; then
  cp -f "$ROOT/android/app/libs/tun2socks.aar" "$GEN/app/libs/"
fi

mkdir -p "$GEN/app/src/main/jniLibs"
cp -f "$ROOT/android/app/src/main/jniLibs/README.md" "$GEN/app/src/main/jniLibs/" 2>/dev/null || true

echo "Готово. JNI: bash scripts/wsl-build-tauri-android-jni.sh"
echo "Затем: cd bibavpn-desktop && npm run tauri:android:build"
