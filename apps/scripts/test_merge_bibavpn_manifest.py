"""Smoke tests for merge_bibavpn_manifest.patch_manifest."""
from merge_bibavpn_manifest import patch_manifest

SAMPLE = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-permission android:name="android.permission.INTERNET" />

    <!-- AndroidTV support -->
    <uses-feature android:name="android.software.leanback" android:required="false" />

    <application
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:theme="@style/Theme.bibavpn_desktop"
        android:usesCleartextTraffic="${usesCleartextTraffic}">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
                <category android:name="android.intent.category.LEANBACK_LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
"""


def test_adds_touchscreen_not_required() -> None:
    patched, changed = patch_manifest(SAMPLE)
    assert changed
    assert 'android.hardware.touchscreen" android:required="false"' in patched


def test_adds_tv_banner() -> None:
    patched, _ = patch_manifest(SAMPLE)
    assert 'android:banner="@drawable/tv_banner"' in patched


def test_idempotent() -> None:
    first, changed1 = patch_manifest(SAMPLE)
    second, changed2 = patch_manifest(first)
    assert changed1
    assert not changed2
    assert first == second


if __name__ == "__main__":
    test_adds_touchscreen_not_required()
    test_adds_tv_banner()
    test_idempotent()
    print("ok")
