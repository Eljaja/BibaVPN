"""Дописывает в Tauri AndroidManifest разрешения и BibaVpnService."""
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


def main() -> None:
    path = pathlib.Path(sys.argv[1])
    t = path.read_text(encoding="utf-8")
    if "BibaVpnService" in t:
        print("manifest already patched")
        return
    if "ACCESS_NETWORK_STATE" not in t:
        t = t.replace(
            '<uses-permission android:name="android.permission.INTERNET" />',
            '<uses-permission android:name="android.permission.INTERNET" />' + PERMS,
            1,
        )
    t = re.sub(r"(</application>)", SERVICE + r"\1", t, count=1)
    if 'android:name=".BibaApplication"' not in t:
        t = t.replace("<application", '<application\n        android:name=".BibaApplication"', 1)
    path.write_text(t, encoding="utf-8")
    print("manifest patched")


if __name__ == "__main__":
    main()
