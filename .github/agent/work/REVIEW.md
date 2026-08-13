VERDICT: PASS

- `completeTunnelForwarding` never calls `completionHandler(nil)`: after settings succeed it stops FFI and completes with `NSError(domain: "BibaVPN", code: 3)` stating Tun2socks is not wired; `tun2socksProxyURL` is kept as the later hook.
- `bibavpn_ios_tunnel_is_active` returns true only for `NEVPNStatus.connected` (`.connecting` / `.reasserting` dropped).
- FFI stop matches the JNI pattern (`done_rx`, `STOP_JOIN_TIMEOUT` 5s, detach on timeout) and is used from `bibavpn_ffi_stop`, start timeout/disconnect cleanup, and the finished-thread restart path; the C header documents the bound.
- Spec-named tests are present and pass: idle `bibavpn_ffi_stop`, stuck-thread detach within ~7s, finished-thread join (`cargo test -p bibavpn-ffi`).
- Docs in README, extras README, `apps/AGENTS.md`, and `ios-ipa.yml` state iOS is experimental / not a working VPN; no IPA attached to Release; no secrets; no edits to `PROTOCOL.md`, `bibavpn/`, or `biba/`.
