# Spec

## Summary

On Android, two connect-failure paths currently look like success to Tauri: VPN permission deny, and `nativeStart` / `startVpnTunnel` failing after the service is queued. Both leave the UI in handshake (`tunnelHandshake`) with `last_error = None` for up to ~120s.

This PR makes deny fail `connect_cmd` immediately, and publishes bootstrap failures into the same `StateSnapshot.error` (`last_error`) the UI already polls and renders. Handshake must stop as soon as either error is visible.

Keep the change inside the existing JNI string + snapshot overlay. Do not add a new Kotlin→Rust event bus.

## In scope

1. **VPN permission deny must fail connect.**
   - `TauriVpnBridge.requestConnect` today returns `null` as soon as the system VPN consent dialog is shown (`startVpnPermissionFlow` + `return null`). `onDenied` only clears pending JSON.
   - Wait for the activity result on the **JNI caller thread**, not on the main looper (waiting on main deadlocks: `onResult` also needs main). Pattern: `runOnUiThread` starts `VpnService.prepare` intent; a `CountDownLatch` is counted down from `onOk` / `onDenied` (same idea as `pickInstalledLauncherPackage`).
   - Return values from `requestConnect` (null = success to start the service):
     - `null` — permission already granted, or user granted and `startWithJson` was called.
     - `vpn_permission_denied` — user denied / canceled (`RESULT_OK` was not returned).
     - keep existing `vpn_permission_ui_unavailable`, `connect_ui_thread_timeout`, `connect_interrupted`.
     - add `vpn_permission_timeout` if the latch expires while the dialog is up.
   - Do **not** start `BibaVpnService` on deny. Keep clearing pending JSON on deny.
   - Rust: treat any non-null JNI string as `Err`. Map the stable codes above to a short Russian user-facing string (same language as other `last_error` values in `lib.rs`) so `connect_cmd` sets `Inner.last_error` and the UI catch in `App.jsx` clears handshake.
   - Raise `android_vpn::request_connect` `recv_timeout` from 60s to **125s** (match pick-package) so the user can finish the system dialog.

2. **Bootstrap failures must reach `StateSnapshot.error`.**
   - After permission is granted, `connect_inner` still returns `Ok` once the service is queued; `enqueueBootstrapWorker` runs later. That async path stays async (do not block `requestConnect` on `nativeStart` — SOCKS bind wait is 20s and would stack with the permission dialog against the JNI timeout).
   - Add a `@Volatile` last-connect-error slot on `BibaVpnService` companion:
     - Set when `nativeStart` returns a non-null error **other than** the existing `already running` skip.
     - Set when `startVpnTunnel()` returns false (stable message, e.g. `vpn_tunnel_start_failed`).
     - Set on the worker’s outer `catch`.
     - Clear when a bootstrap attempt **starts**, and when the tunnel becomes active (`setTunnelActive(true)`).
   - Keep the existing Toast + `stopSelf()` behavior; it is not the UI channel.
   - Expose `TauriVpnBridge.lastConnectError(): String?` (and a clear method) via JNI.
   - Android `snapshot` / `get_state`: if the tunnel is **not** active, overlay this JNI string into `StateSnapshot.error` when `Inner.last_error` is `None`. If the tunnel **is** active, do not overlay (stale bootstrap error must not win over `connected`; ConnectScreen treats `snap.error` as higher priority than connected).
   - `clear_error_cmd` and Android `disconnect_inner` must clear the Kotlin slot as well as `Inner.last_error`.

3. **Stop handshake on error.**
   - `App.jsx`: in addition to clearing `tunnelHandshake` on `snap.connected` / `connect()` catch / 120s timeout, clear it when `snap.error` is set.
   - No new UI chrome: ConnectScreen already shows `snap.error` and switches `cs` to `"error"` when it is present.

## Out of scope

- iOS / desktop `connect_inner`.
- New Tauri events or a Kotlin→`AppHandle` callback; handshake already polls `get_state` every 650ms while `tunnelHandshake` is true.
- Blocking `requestConnect` until `nativeStart` / tun2socks complete.
- Removing Toasts, changing notification copy, or VPN-consent UX besides fail vs success.
- Failures on later full-stack restarts (`requestFullStackRestart`, network / screen-on). Reuse the same setter only if it is a one-line call from `enqueueBootstrapWorker`; do not expand those paths.
- Wire format, `bibavpn` / `bibavpn-jni` / `biba` crates, invite JSON.
- New emulator / device CI jobs.

## Files to change

- `apps/bibavpn-desktop/src-tauri/android-bibavpn-extras/java/dev/bibavpn/TauriVpnBridge.kt` — wait for permission result; return deny/timeout codes; JNI getter/clear for last connect error.
- `apps/bibavpn-desktop/src-tauri/android-bibavpn-extras/java/dev/bibavpn/BibaVpnService.kt` — last-connect-error slot; set/clear from `enqueueBootstrapWorker` and `setTunnelActive(true)`.
- `apps/bibavpn-desktop/src-tauri/src/android_vpn.rs` — longer connect timeout; `last_connect_error` / `clear_last_connect_error` JNI; keep treating non-null `requestConnect` as `Err`.
- `apps/bibavpn-desktop/src-tauri/src/lib.rs` — cfg-independent mapper from JNI codes → user-facing `last_error` (so Linux CI can test it); Android `snapshot` overlay; `clear_error_cmd` + Android disconnect clear the Kotlin slot.
- `apps/bibavpn-desktop/ui/src/App.jsx` — drop `tunnelHandshake` when `snap.error` is set.

Do not edit `.github/agent/work/ISSUE.md` or this spec file from the implementation PR except as required by the agent workflow.

## Tests

This is an Android UI/JNI change, not the tunnel crate. Do **not** add a device/emulator harness.

Run (same as CI):

```bash
cargo test -p bibavpn-desktop --locked
```

Add unit tests in `lib.rs` (always compiled, not `cfg(target_os = "android")`) for:

- JNI status mapping: `vpn_permission_denied`, `vpn_permission_timeout`, `vpn_permission_ui_unavailable` → non-empty user-facing strings; unknown strings pass through; empty/`null` is success.
- Snapshot overlay: inactive tunnel + JNI error + empty `last_error` → `error` is the JNI text; active tunnel ignores JNI overlay; existing `last_error` wins over JNI when both are set.

`android_vpn.rs` is `cfg(target_os = "android")` and will not run on the Linux CI host; keep behavioral tests in the cfg-independent helper.

Do not run `cargo test -p bibavpn` unless a follow-up accidentally touches that crate (this spec does not).

Manual (not CI): on an Android device/emulator, deny VPN permission and confirm the Connect screen shows the error and leaves handshake; force a bootstrap failure (bad config / `nativeStart` error) and confirm `snap.error` appears without waiting 120s.

## Acceptance criteria

- Denying the VPN permission fails `connect_cmd` (`last_error` / `StateSnapshot.error` set). The Connect screen shows the error and is **not** left in handshake (`status_handshaking`). The VPN service is not started.
- A `nativeStart` error (other than already-running) or `startVpnTunnel() == false` becomes visible in the app UI via `StateSnapshot.error` within one handshake poll (~1s), not only as a Toast. Handshake stops when that error appears.
- A successful connect still reaches connected; a stale bootstrap error cannot override `connected` in the UI.
- Dismissing the error (`clear_error_cmd`) clears both Rust `last_error` and the Kotlin slot.
- `cargo test -p bibavpn-desktop --locked` passes.

## Non-goals

- Making Android `connect_inner` wait until the tun interface is up.
- Changing proto 3, REALITY, SOCKS, or server behavior.
- Localizing `last_error` through `i18n.js` (backend strings stay as today).
- Redesigning ConnectScreen error presentation.
- Guaranteeing coverage of every `BibaVpnService` restart path in this PR.
