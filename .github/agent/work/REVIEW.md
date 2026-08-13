VERDICT: PASS

- VPN permission wait is on a worker/`CountDownLatch`, not the main looper; deny returns `vpn_permission_denied` and does not start `BibaVpnService`; timeout/UI-unavailable/interrupted codes are preserved; Rust `request_connect` timeout is 125s.
- `connect_inner` maps those JNI codes to Russian `last_error`, so `connect_cmd` fails immediately and the existing `App.jsx` catch drops handshake.
- Bootstrap errors (`nativeStart` other than already-running, `vpn_tunnel_start_failed`, worker catch) go into the Kotlin slot; `snapshot` overlays them only when the tunnel is inactive and Rust `last_error` is empty; active tunnel ignores the overlay.
- `clear_error_cmd` and Android `disconnect_inner` clear the Kotlin slot; `App.jsx` also clears `tunnelHandshake` when `snap.error` is set.
- Named `lib.rs` unit tests cover JNI mapping (known codes, passthrough, empty) and overlay (inactive / active / last_error wins). Change set is the five spec files only; no new event bus, no tunnel-crate edits, no secrets.
