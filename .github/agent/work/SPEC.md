SIZE: SMALL
# Spec
## Summary

Android and iOS `snapshot()` in `apps/bibavpn-desktop/src-tauri/src/lib.rs` waits on tunnel callbacks (`tunnel_is_active`, then uptime, then Android `last_connect_error`) while callers still hold `Mutex<Inner>`. Those waits serialize other save/import/connect/disconnect/tray work. Split the snapshot into a short locked copy, a lock-free probe, and an epoch-gated assemble so a late probe cannot revive connected state, an old profile, or a stale error. Persistence, combined JNI, Settings, and fonts stay out.

## In scope

1. **`Inner.epoch: u64`** (start at `0`). Bump under the lock on: disconnect start (when clearing `tunnel_server`); connect completion (success that sets `tunnel_server`, or a mapped failure that writes `last_error`); successful `apply_invite_to_cfg`; `apply_pending_import` apply; successful `save_config_cmd` after `merge_saved_config`. Do not reuse `VpnPhase` / `ConnectingPhaseGuard` (desktop-only). Do not persist epoch.

2. **Replace `snapshot(app, &inner)` held across probes** with a shared helper used by every listed caller:
   - Brief lock: copy `to_public_saved_config(&inner.cfg)`, `display_host` / `server_subtitle`, `tunnel_server`, `last_error`, `can_connect`, `epoch`. Desktop `connected` is `inner.vpn.is_some()` and needs no probe.
   - Drop `Inner`. Android/iOS probe **without** `Inner`. Keep `VPN_WEBVIEW_JNI_MUTEX` and existing 5s / 18s timeouts. Never call Kotlin/Swift while holding `Inner`.
   - Re-lock and assemble. If `epoch` is unchanged, attach probe `connected` / uptime. If `epoch` changed, **discard** the probe; rebuild cfg/error/`tunnel_server` from current `Inner`. If `tunnel_server` is `None`, force `connected = false` and no uptime. Do not write probe fields back into `Inner`.
   - `android_snapshot_error` stays: Rust `last_error` wins; JNI error overlays only when the tunnel is inactive. Timeouts stay errors (`map_android_jni_connect_error` / existing strings); do not invent success.

3. **Wire every current `snapshot()` holder**, including:
   - `get_state`
   - `save_config_cmd`
   - `apply_invite_cmd`
   - `apply_pending_import` / `confirm_pending_import_cmd`
   - `clear_error_cmd` — drop `Inner` before `clear_last_connect_error`, then assemble
   - `connect_cmd` success and error snapshots
   - Android / iOS `connect_inner` post-connect `tunnel_is_active` (copy tray inputs, drop, probe, short lock for tray + epoch)
   - Android / iOS `disconnect_inner` (keep `connected = false` override after a successful stop)
   - `disconnect_cmd` follow-up snapshot
   - `open_control_plane_refresh_cmd` final snapshot
   Pre-connect “already active?” probes in `connect_inner` already run without `Inner`; leave that order.

4. **`spawn_blocking` for today’s sync commands that can JNI-wait** (`get_state`, `save_config_cmd`, `clear_error_cmd`, `apply_invite_cmd`, `confirm_pending_import_cmd`, and the refresh snapshot). Match `connect_cmd` / `get_tunnel_status_cmd`: do not add a worker that the UI thread then joins.

5. **Extract assemble + epoch** into a unit-testable function that takes copied fields plus a `TunnelProbe` (or injected closures), not live JNI/`AppHandle`.

## Out of scope

- Moving `persist_cfg` / `fs::write` off `Inner`, persist mutex / `write_seq`.
- Combined Kotlin `tunnelSnapshot()`; removing or reordering `VPN_WEBVIEW_JNI_MUTEX`.
- Settings keystroke / package-list / font bundling.
- Changing `get_tunnel_status_cmd` (already `spawn_blocking`, no `Inner` on Android/iOS) or restoring full-config polling in `App.jsx` / `ConnectScreen.jsx` / `useVpn.jsx`.
- `bibavpn` / `biba` crates, PROTOCOL, invite URI, REALITY, Kotlin/Swift API changes.

## Files to change

- `apps/bibavpn-desktop/src-tauri/src/lib.rs` — `Inner.epoch`; split copy/probe/assemble; all callers above; `Inner { … }` literals at startup (~L1175), any other constructor (~L1944), and `deeplink_tests` (~L2174); new unit tests next to `android_connect_error_tests`.
- `apps/bibavpn-desktop/src-tauri/src/android_vpn.rs` — no API change unless a thin probe wrapper is needed; keep mutex and timeouts.
- `apps/bibavpn-desktop/src-tauri/src/ios_vpn.rs` — same lock-free probe contract (`tunnel_is_active` 18s must not run under `Inner`).
- `apps/bibavpn-desktop/src-tauri/src/config.rs` — do not change `to_public_saved_config` (callers must still use it).

## Tests

```bash
cargo test -p bibavpn-desktop
npm run build --prefix apps/bibavpn-desktop/ui
```

Do **not** run `cargo test -p bibavpn` (core crate untouched). No new harness, Perfetto, or device CI.

Required cases (inject probe; no live JNI):

- Contending lock: a probe that sleeps (e.g. 200ms) does not hold `Inner`; a second thread acquires the mutex in well under that sleep.
- Epoch bump + `tunnel_server = None` while a probe is in flight → assembled `connected == false`, no uptime, current cfg/error (not the pre-disconnect copy).
- Import / invite-style cfg replace bumps epoch → late probe cannot emit the old public cfg.
- `android_snapshot_error`: Rust `last_error` wins; permission-denial overlay only when inactive; empty/timeout strings are not success.
- Assembled `cfg` still goes through `to_public_saved_config` (no `token` / `psk` / invite / PEM in the public payload).
- Desktop path: `connected` follows `vpn.is_some()` with no probe.
- Existing `android_connect_error_tests` and `deeplink_tests` still pass.

## Acceptance criteria

- Listed full-snapshot / connect / save / invite / import / clear-error / disconnect / refresh paths do not hold `Inner` while waiting on Android/iOS tunnel callbacks.
- A delayed mocked probe does not block unrelated `Inner` access for the duration of that wait.
- A late probe cannot restore stale connected state, apply a pre-import/pre-save profile, erase a newer `last_error`, or undo disconnect (`tunnel_server == None` → disconnected).
- Permission denial, bootstrap failure, cancellation, and connect/disconnect errors stay visible; JNI timeout is not mapped to success.
- Public `vpn-state` / `StateSnapshot` payloads keep #87 redaction.
- `get_tunnel_status_cmd` keeps its in-flight/`cancelled` UI contract; no extra timers or full-config polls.
- `cargo test -p bibavpn-desktop` and `npm run build --prefix apps/bibavpn-desktop/ui` pass. Device traces are not required; do not claim a frame-time win.

## Non-goals

- Do not remove all mutexes, switch UI frameworks, or change the VPN protocol.
- Do not debounce Settings input or bundle Google Fonts.
- Do not persist-outside-lock or combine the three JNI queries in this PR.
- Do not enable `ConnectingPhaseGuard` on Android/iOS.
- Do not invent success to hide a timeout, or treat the 5s/18s bounds as typical latency.
