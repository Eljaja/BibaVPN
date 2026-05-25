#!/usr/bin/env bash
# После `tauri android init`: копирует VPN-слой из Tauri extras в gen/android.
# Запуск из корня репозитория biba-vpn:
#   bash apps/scripts/integrate-bibavpn-into-tauri-android.sh
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
GEN="$ROOT/apps/bibavpn-desktop/src-tauri/gen/android"
EXTRAS="$ROOT/apps/bibavpn-desktop/src-tauri/android-bibavpn-extras"

if [ ! -d "$GEN/app" ]; then
  echo "Нет $GEN — сначала tauri android init" >&2
  exit 1
fi

APP_JAVA="$GEN/app/src/main/java/dev/bibavpn"
mkdir -p "$APP_JAVA/core"
for f in BibaVpnService.kt TauriVpnBridge.kt BibaApplication.kt AppLocale.kt PickInstalledPackageActivity.kt; do
  cp -f "$EXTRAS/java/dev/bibavpn/$f" "$APP_JAVA/"
done
cp -f "$EXTRAS/java/dev/bibavpn/core/BibaNative.kt" "$APP_JAVA/core/"
cp -f "$EXTRAS/java/dev/bibavpn/core/VpnProtect.kt" "$APP_JAVA/core/"

mkdir -p "$GEN/app/src/main/res/drawable"
cp -f "$EXTRAS/res/drawable/ic_stat_vpn.xml" "$GEN/app/src/main/res/drawable/"
cp -f "$EXTRAS/res/drawable/tv_banner.xml" "$GEN/app/src/main/res/drawable/"

# Строки только для VPN-уведомлений (не перетираем strings Tauri)
EXR="$EXTRAS/res"
mkdir -p "$GEN/app/src/main/res/values"
cp -f "$EXR/values/bibavpn_vpn_strings.xml" "$GEN/app/src/main/res/values/"

python3 "$SCRIPT_DIR/merge_bibavpn_manifest.py" "$GEN/app/src/main/AndroidManifest.xml"

# Зависимости tun2socks — Groovy-фрагмент (apply(from) для .kts не даёт scope на implementation).
EXTRAS="$GEN/app/bibavpn-vpn-extras.gradle"
rm -f "$GEN/app/bibavpn-vpn-extras.gradle.kts"
cat > "$EXTRAS" << 'EOF'
dependencies {
    def tun2socksAar = file("${project.projectDir}/libs/tun2socks.aar")
    if (tun2socksAar.exists()) {
        implementation(files(tun2socksAar))
    } else {
        implementation("com.ooimi.library:tun2socks:1.0.4")
    }
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.lifecycle:lifecycle-service:2.7.0")

    // PickInstalledPackageActivity (split-tunnel)
    implementation("androidx.recyclerview:recyclerview:1.3.2")
}
EOF

BG="$GEN/app/build.gradle.kts"
if [ -f "$BG" ]; then
  if grep -q 'bibavpn-vpn-extras.gradle.kts' "$BG"; then
    sed -i 's/bibavpn-vpn-extras\.gradle\.kts/bibavpn-vpn-extras.gradle/g' "$BG"
  elif ! grep -q 'bibavpn-vpn-extras' "$BG"; then
    echo "" >> "$BG"
    echo '// BibaVPN native VPN + tun2socks' >> "$BG"
    echo 'apply(from = "bibavpn-vpn-extras.gradle")' >> "$BG"
  fi
  # R8 в release ломает Tauri/Wry (NoClassDefFoundError, без стека) — выключаем minify, пока нет полного набора keep rules.
  if grep -q 'isMinifyEnabled = true' "$BG"; then
    sed -i 's/isMinifyEnabled = true/isMinifyEnabled = false \/\/ BibaVPN: R8+Tauri WebView/' "$BG" || true
  fi
  python3 << PY
from pathlib import Path
p = Path("$BG")
text = p.read_text()
compose_block = """    buildFeatures {
        buildConfig = true
        compose = true
    }
    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.15"
    }
"""
plain = """    buildFeatures {
        buildConfig = true
    }
"""
if compose_block in text:
    p.write_text(text.replace(compose_block, plain, 1))
PY
fi

mkdir -p "$GEN/app/libs"
if [ -f "$EXTRAS/libs/tun2socks.aar" ]; then
  cp -f "$EXTRAS/libs/tun2socks.aar" "$GEN/app/libs/"
fi

mkdir -p "$GEN/app/src/main/jniLibs"
cp -f "$EXTRAS/jniLibs/README.md" "$GEN/app/src/main/jniLibs/" 2>/dev/null || true

# ProGuard: release minify (R8) must keep Tauri/Wry/WebView — без этого вылет NoClassDefFoundError после WebView.
cp -f "$ROOT/apps/bibavpn-desktop/src-tauri/android-bibavpn-extras/proguard-bibavpn.pro" "$GEN/app/proguard-bibavpn.pro"

# Адаптивные иконки (API 26+) + цвет фона; без mipmap-anydpi-v26 в лаунчере пусто/дефолт.
ICNS="$ROOT/apps/bibavpn-desktop/src-tauri/icons/android"
if [ -d "$ICNS/mipmap-anydpi-v26" ]; then
  mkdir -p "$GEN/app/src/main/res"
  cp -fR "$ICNS/mipmap-anydpi-v26" "$GEN/app/src/main/res/"
fi
if [ -f "$ICNS/values/ic_launcher_background.xml" ]; then
  mkdir -p "$GEN/app/src/main/res/values"
  cp -f "$ICNS/values/ic_launcher_background.xml" "$GEN/app/src/main/res/values/"
fi

echo "Готово. JNI: bash apps/scripts/wsl-build-tauri-android-jni.sh"
echo "Затем: cd apps/bibavpn-desktop && npm run tauri:android:build"
