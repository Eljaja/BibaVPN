# Spec

## Summary

Issue #73 is a wishlist: iOS Packet Tunnel reports **Connected** without bridging `packetFlow` to SOCKS, the host UI treats `.connecting` / `.reasserting` as on, `bibavpn_ffi_stop` can hang on an unbounded `join()`, and there is no Network Extension equivalent of Android `VpnService.protect`.

This PR ships the smallest honest slice: **do not report a working VPN**. Fail tunnel start with a clear error instead of `completionHandler(nil)`, treat only NE `.connected` as active in the host bridge, bound FFI stop the same way Android JNI does (5s then detach), and document iOS as experimental / not a working VPN. Full tun2socks wiring and an NE protect/bind hook stay out of this PR.

## In scope

- **Fail start instead of lying Connected.** In `PacketTunnelProvider.completeTunnelForwarding`, never call `completionHandler(nil)`. After `setTunnelNetworkSettings` succeeds, call `bibavpn_ffi_stop()` (SOCKS may already be running) and complete with an `NSError` (domain `BibaVPN`, unused code such as `3`) whose localized description states that packet forwarding is not implemented on iOS (Tun2socks not wired) and the tunnel cannot start. Keep `tun2socksProxyURL` and the gomobile comments as the hook for a later PR.
- **Host UI: only `.connected` is active.** In `bibavpn_ios_tunnel_is_active`, drop `.connecting` and `.reasserting` from the “on” cases. Return true only for `NEVPNStatus.connected`.
- **Bounded FFI stop (JNI parity).** In `apps/bibavpn-ffi`, copy the Android pattern from `apps/bibavpn-jni/src/lib.rs`:
  - Add `done_rx: Option<Receiver<()>>` on `NativeState`.
  - In the client thread, hold a `done_tx` that drops when the closure returns (after the tokio runtime is dropped).
  - Extract `stop_client_bounded` with `STOP_JOIN_TIMEOUT = 5s`: signal shutdown, `recv_timeout` on `done_rx`, join only if the sender disconnected, otherwise warn and detach the `JoinHandle`.
  - Use it from `bibavpn_ffi_stop`, from the SOCKS-ready timeout/disconnect cleanup in `bibavpn_ffi_start`, and from the “previous thread finished” restart path (replace unbounded `h.join()`).
  - Update the C header comment: stop is idempotent and returns within ~5s even if the client thread is stuck.
- **Docs (honesty, no working-IPA claim).**
  - `README.md` “Android & desktop”: iOS Packet Tunnel exists but **does not forward traffic**; it is experimental and must not be presented as a working VPN.
  - `apps/bibavpn-desktop/src-tauri/ios-bibavpn-extras/README.md`: start currently **fails** until Tun2socks is wired; the gomobile script remains a follow-up.
  - `apps/AGENTS.md` Tauri iOS section: one line that Packet Tunnel start fails until forwarding is implemented.
  - `.github/workflows/ios-ipa.yml` header: IPA is a signing/dev smoke artifact, **not** a working VPN. Do **not** attach IPA to GitHub Release (`release.yml` already omits it; do not add it).

## Out of scope

- Wiring Tun2socks / gomobile `Engine` into `completeTunnelForwarding` (`packetFlow` / TUN fd, `Tun2socks.xcframework` link, XcodeGen changes).
- iOS equivalent of Android `VpnService.protect` / `outbound_protect` bind-before-connect (needed only after tun2socks actually routes into the TUN).
- Changing proto-3 wire format, `bibavpn` / `biba` crates, Android JNI, or desktop non-iOS paths.
- Shipping or advertising a working iOS VPN / IPA on Releases.
- New Swift/XCTest or device CI harnesses.
- Session-elapsed timer (`kTunnelStarted` set at `startVPNTunnel()`); only `tunnel_is_active` is in this slice.

## Files to change

- `apps/bibavpn-desktop/src-tauri/ios-bibavpn-extras/BibaVpnTunnel/PacketTunnelProvider.swift` — fail in `completeTunnelForwarding`.
- `apps/bibavpn-desktop/src-tauri/ios-bibavpn-extras/host-sources/BibaVpnAppleBridge.swift` — `bibavpn_ios_tunnel_is_active` only `.connected`.
- `apps/bibavpn-ffi/src/lib.rs` — `stop_client_bounded` + `done_rx`; unit tests in `#[cfg(test)]`.
- `apps/bibavpn-ffi/include/bibavpn_ffi.h` — document bounded stop.
- `README.md` — iOS experimental / not forwarding.
- `apps/bibavpn-desktop/src-tauri/ios-bibavpn-extras/README.md` — start fails until tun2socks.
- `apps/AGENTS.md` — one-line iOS caveat.
- `.github/workflows/ios-ipa.yml` — comment that IPA is not a working VPN.

Do not edit `PROTOCOL.md`, `bibavpn/`, or `biba/`.

## Tests

No new test harness. Swift extras have none; do not add XCTest.

1. **Bounded stop (required)** — `cargo test -p bibavpn-ffi`:
   - Idle `stop_client_bounded` / `bibavpn_ffi_stop` returns quickly when `STATE` is `None`.
   - A `NativeState` whose thread never finishes and whose `done_tx` is held: `stop_client_bounded` returns within `STOP_JOIN_TIMEOUT` plus a small slack (e.g. 7s), does not panic, and detaches rather than blocking forever.
   - After a thread that does finish, stop joins without hitting the timeout warn path.
2. **Clippy (recommended)** — `cargo clippy -p bibavpn-ffi -- -D warnings`.
3. **Do not require** `cargo test -p bibavpn` or `-p biba` (those crates are untouched).
4. **Manual (macOS / device, not CI):** start the Packet Tunnel → system VPN and Tauri UI stay disconnected (or show a start error), never Connected; disconnect/stop returns in a few seconds.

## Acceptance criteria

- Starting the iOS Packet Tunnel **fails** with a clear error; the system VPN UI does **not** stay Connected with no routed traffic.
- `bibavpn_ios_tunnel_is_active` is true only when NE status is `.connected` (false for `.connecting` and `.reasserting`).
- `bibavpn_ffi_stop` returns within about 5 seconds even if the client thread is stuck on DNS/connect; `cargo test -p bibavpn-ffi` covers the stuck-thread case.
- README / extras README / `apps/AGENTS.md` / `ios-ipa.yml` state that iOS is experimental and does not forward traffic; GitHub Release still does not publish an IPA as a working VPN.

## Non-goals

- A device that can reach the internet via the VPS (egress-IP proof). That is the tun2socks follow-up, not this PR.
- NE-aware socket protect/bind, split-tunnel completeness, or IPv6 excluded-route hardening beyond what already exists.
- Changing default client/server protocol, stealth, or Android behavior.
- Making `ios-ipa.yml` a release job or deleting the gomobile tun2socks script.
