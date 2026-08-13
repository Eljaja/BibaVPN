# Spec

## Summary

Android domain split-tunnel still fails for users because the TUN only sees IPs, and the current `VpnService.excludeRoute` workaround is IPv4-only, resolve-once, API 33+, and capped. The tunnel client already has the right enforcement layer: `bibavpn::domain_route` (DNS-answer snoop → IP→domain map → SOCKS `CONNECT` goes `Direct` via `outbound_protect`). This PR does **not** rebuild that. It ships the missing piece that makes it work when plaintext DNS is invisible (Android Private DNS / DoH / resolver cache): **peek TLS ClientHello SNI** on SOCKS `CONNECT` to an IP, and stop using `excludeRoute` as the Android domain enforcer so shared CDN IPs are not excluded wholesale.

Desktop hostname split (system HTTP/SOCKS proxy) stays as-is.

## In scope

1. **SNI fallback on SOCKS `CONNECT` (Android full-TUN path).** After a successful SOCKS `CONNECT` to a **literal IP** on port **443**, if `domain_route::should_bypass(ip)` is false and a bypass list is installed, read the first TLS record from the local stream (short timeout), extract the ClientHello SNI, and if `matches_bypass` then `Direct` (protected connect + write the peeked bytes, then `copy_bidirectional`). Otherwise keep today’s tunnel/mux path and forward the peeked bytes as existing `client_prefetch`. Fail-safe: timeout / non-TLS / no SNI → **Tunnel**.
2. **Same `should_bypass(host)` on HTTP CONNECT** before opening a tunnel stream (hostname literals already work; IP+443 uses the same SNI peek). Needed so the decision lives in one place in `local_client.rs`.
3. **Minimal SNI extractor** (pure, no I/O) next to the DNS parser — parse one TLS record + ClientHello SNI extension only. Do not reuse REALITY `extract_sni` or the `biba` fingerprint parser.
4. **Stop applying domain `excludeRoute`.** `Builder.applySplitTunnelDomainBypasses()` must no longer exclude resolved IPs. Per-app `addDisallowedApplication` is unchanged. Domain lists still flow into start JSON as `split_bypass_domains` (already wired in `TunnelProfile::start_config_json` / `start_json_config`).
5. **UI copy.** Replace `android_split_note` (ru + en) so it no longer claims domain bypass is Android 13+ / resolve-at-connect. Domain presets apply on all API levels via the tunnel client; per-app bypass remains available. Do **not** add a “domain split unavailable on Android &lt; 13” banner — that was for `excludeRoute`, which this PR stops using.
6. **Logging.** One `bibavpn_client` debug/info line when a stream is routed `Direct` (host or recovered SNI, not the full bypass list). No secrets.

## Out of scope

- Dynamic `excludeRoute` / VPN re-establish / periodic `getAllByName` refresh / raising `MAX_DOMAIN_ROUTE_EXCLUSIONS` / IPv6 `excludeRoute`.
- Android Private DNS settings, DoH catalog, or forcing plaintext DNS.
- HTTP `Host` peek, QUIC/HTTP3 SNI, TLS 1.3 Encrypted Client Hello.
- UDP datagram bypass (DNS to 8.8.8.8 stays tunneled; QUIC to a bypassed name stays tunneled).
- Adding `::/0` / IPv6 TUN (today IPv6 is not captured; do not expand the TUN in this PR).
- iOS Packet Tunnel, desktop WinInet/macOS/Linux proxy-override behavior, wire-format / proto-3 changes.
- Fake-DNS in tun2socks.

## Files to change

- `bibavpn/src/domain_route.rs` — `extract_client_hello_sni(&[u8]) -> Option<String>` + unit tests (malformed, no SNI, IPv4/IPv6 literals ignored, suffix match via existing `matches_bypass`).
- `bibavpn/src/local_client.rs` — SOCKS `CONNECT` and HTTP CONNECT: `should_bypass`; on miss + IP:443, peek then Direct vs tunnel with prefetch. Extend `direct_bypass_relay` to accept optional peeked prefix bytes.
- `apps/bibavpn-desktop/src-tauri/android-bibavpn-extras/java/dev/bibavpn/BibaVpnService.kt` — do not call `applySplitTunnelDomainBypasses()` from `startVpnTunnel` (leave the function as a no-op or delete the call; do not keep IP exclusions).
- `apps/bibavpn-desktop/ui/src/i18n.js` — `android_split_note` ru/en.
- `apps/bibavpn-desktop/src-tauri/src/split_tunnel.rs` — comment only: Android domains are for `split_bypass_domains`, not `excludeRoute`.
- Optional: `bibavpn/tests/split_bypass_wiring.rs` — one SNI-style assertion is **not** required there (it mutates process-global state); keep SNI tests in `domain_route` unit tests.

Do not change `PROTOCOL.md`.

## Tests

```bash
cargo test -p bibavpn
```

Must keep passing existing `domain_route` unit tests and `bibavpn/tests/split_bypass_wiring.rs`.

Add unit tests in `domain_route.rs` (or the same module) for:

- Valid TLS ClientHello → SNI `example.com`.
- Truncated / non-handshake record → `None`.
- SNI `a.example.com` + bypass `example.com` → `matches_bypass` true; `notexample.com` false.

No new device/Gradle/tun2socks harness. Manual Android check (not CI): connect with a bypass preset, open an HTTPS site on that domain, confirm egress is the device IP not the VPS (and a non-bypass site still egresses via the VPS).

If comments-only desktop files are touched, no extra crate test is required. If `config.rs` / `split_tunnel.rs` logic were changed (this spec says they should not be), then also `cargo test -p bibavpn-desktop`.

## Acceptance criteria

- With split tunnel enabled and a domain preset selected, an HTTPS (TCP/443) connection to that domain on Android egresses **outside** the tunnel (protected direct connect), including when the app used DoH/Private DNS so UDP/53 was never snooped, as long as the ClientHello SNI matches the preset (suffix rules unchanged).
- CDN IP churn: a new A/AAAA learned via UDP/53 still Direct via the existing map; a new IP with no DNS map still Direct if SNI matches.
- Shared CDN IP: a connection whose SNI is **not** on the bypass list stays **Tunnel** (this is why `excludeRoute` is removed).
- Android &lt; 13: domain presets still apply (SOCKS-layer path). Per-app bypass unchanged. UI does not say domain split is unavailable.
- Bypass list empty: no peek, no Direct, same as today.
- Desktop domain split via system proxy hostnames is unchanged.
- `cargo test -p bibavpn` passes.

## Non-goals

- Perfect split for every protocol (UDP, QUIC, ECH, plaintext HTTP-to-IP).
- Capturing or splitting IPv6 at the TUN.
- Making `excludeRoute` correct on API 33+.
- Changing proto 3, REALITY, or server code.
- New metrics, settings toggles, or a “force SNI peek” flag — peek only when a non-empty bypass list is installed.
