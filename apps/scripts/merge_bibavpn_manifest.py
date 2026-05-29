"""Дописывает в Tauri AndroidManifest разрешения, TV-совместимость, AppLocales и BibaVpnService."""
import pathlib
import re
import sys

PERMS = """
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    <uses-permission android:name="android.permission.WAKE_LOCK" />
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE_SPECIAL_USE" />
    <uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
    <uses-permission android:name="android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS" />
"""

# Без touchscreen required=false Android TV часто отклоняет установку («Приложение не установлено»).
TV_FEATURES = """
    <uses-feature android:name="android.hardware.touchscreen" android:required="false" />
    <uses-feature android:name="android.hardware.faketouch" android:required="false" />
    <uses-feature android:name="android.hardware.telephony" android:required="false" />
    <uses-feature android:name="android.hardware.camera" android:required="false" />
    <uses-feature android:name="android.hardware.microphone" android:required="false" />
    <uses-feature android:name="android.hardware.location" android:required="false" />
    <uses-feature android:name="android.hardware.location.gps" android:required="false" />
    <uses-feature android:name="android.hardware.bluetooth" android:required="false" />
"""

# Нужен для setApplicationLocales / AppCompat; без meta лог: AppLocalesMetadataHolderService not found
APP_LOCALES_SERVICE = """
        <service
            android:name="androidx.appcompat.app.AppLocalesMetadataHolderService"
            android:enabled="false"
            android:exported="false">
            <meta-data
                android:name="autoStoreLocales"
                android:value="true" />
        </service>
"""

SERVICE = """
        <service
            android:name=".BibaVpnService"
            android:exported="false"
            android:foregroundServiceType="specialUse"
            android:permission="android.permission.BIND_VPN_SERVICE">
            <property
                android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE"
                android:value="User VPN tunnel: BibaVPN (TUN + SOCKS)." />
            <intent-filter>
                <action android:name="android.net.VpnService" />
            </intent-filter>
        </service>
"""

PICK_PACKAGE_ACTIVITY = """
        <activity
            android:name=".PickInstalledPackageActivity"
            android:exported="false"
            android:theme="@style/Theme.AppCompat.Dialog" />
"""

DEEPLINK_INTENT = """
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="bibavpn" android:host="import" />
            </intent-filter>
"""


def _insert_after_internet_perm(text: str, block: str) -> str:
    if block.strip() in text:
        return text
    needle = '<uses-permission android:name="android.permission.INTERNET" />'
    if needle not in text:
        return text
    return text.replace(needle, needle + block, 1)


def _ensure_tv_features(text: str) -> str:
    if 'android.hardware.touchscreen' in text:
        return text
    if 'android.software.leanback' in text:
        return text.replace(
            '<uses-feature android:name="android.software.leanback" android:required="false" />',
            '<uses-feature android:name="android.software.leanback" android:required="false" />' + TV_FEATURES,
            1,
        )
    return _insert_after_internet_perm(text, TV_FEATURES)


def _ensure_tv_banner(text: str) -> str:
    if 'android:banner=' in text:
        return text
    return re.sub(
        r"(<application\s)",
        r'\1android:banner="@drawable/tv_banner" ',
        text,
        count=1,
    )


def _ensure_biba_application(text: str) -> str:
    if 'android:name=".BibaApplication"' in text:
        return text
    return text.replace(
        "<application",
        '<application\n        android:name=".BibaApplication"',
        1,
    )


def patch_manifest(text: str) -> tuple[str, bool]:
    original = text
    text = _insert_after_internet_perm(text, PERMS)
    text = _ensure_tv_features(text)
    text = _ensure_tv_banner(text)
    text = _ensure_biba_application(text)

    if "AppLocalesMetadataHolderService" not in text:
        text = re.sub(
            r"(<application\s[^>]*>)",
            r"\1" + APP_LOCALES_SERVICE,
            text,
            count=1,
        )

    if "BibaVpnService" not in text:
        text = re.sub(r"(</application>)", SERVICE + r"\1", text, count=1)

    if "PickInstalledPackageActivity" not in text:
        text = re.sub(r"(</application>)", PICK_PACKAGE_ACTIVITY + r"\1", text, count=1)

    if 'android:scheme="bibavpn"' not in text:
        text = re.sub(
            r"(<activity[^>]*android:name=\"\.MainActivity\"[^>]*>)",
            r"\1" + DEEPLINK_INTENT,
            text,
            count=1,
        )

    return text, text != original


def main() -> None:
    path = pathlib.Path(sys.argv[1])
    patched, changed = patch_manifest(path.read_text(encoding="utf-8"))
    if changed:
        path.write_text(patched, encoding="utf-8")
        print("manifest patched")
    else:
        print("manifest already patched")


if __name__ == "__main__":
    main()
