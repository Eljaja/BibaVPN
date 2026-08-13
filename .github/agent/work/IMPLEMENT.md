# Implementation

## Tests

`cargo test -p bibavpn-desktop --locked` — **23 passed** (after `npm run build` in `apps/bibavpn-desktop/ui` and installing GTK/WebKit system deps on the Linux runner).

## Changes

### VPN permission deny fails connect immediately

- `TauriVpnBridge.requestConnect` waits for the system VPN consent dialog on the JNI caller thread (`CountDownLatch` + `runOnUiThread`, same pattern as `pickInstalledLauncherPackage`).
- Returns `vpn_permission_denied`, `vpn_permission_timeout`, or existing error codes; does not start `BibaVpnService` on deny.
- `android_vpn::request_connect` recv timeout raised to **125s**.
- Rust maps JNI codes to Russian user-facing strings via `map_android_jni_connect_error`; `connect_inner` propagates them as `last_error`.

### Bootstrap failures reach `StateSnapshot.error`

- `BibaVpnService` companion holds `@Volatile lastConnectError`; set on `nativeStart` failure (except already-running), `startVpnTunnel() == false`, and worker catch; cleared at bootstrap start and `setTunnelActive(true)`.
- Exposed via `TauriVpnBridge.lastConnectError()` / `clearLastConnectError()` JNI.
- Android `snapshot` overlays JNI error into `StateSnapshot.error` when tunnel inactive and `Inner.last_error` is `None`.
- `clear_error_cmd` and Android `disconnect_inner` clear the Kotlin slot.

### Handshake stops on error

- `App.jsx` clears `tunnelHandshake` when `snap.error` is set (in addition to connected / catch / 120s timeout).
