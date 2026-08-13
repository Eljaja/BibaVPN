# Implementation summary

## What changed

1. **`bibavpn/src/domain_route.rs`**
   - Added `extract_client_hello_sni` — minimal pure TLS ClientHello SNI parser (one record, no I/O).
   - Added `bypass_domains_active` and `matches_active_bypass` helpers for the SOCKS/HTTP path.
   - Unit tests: valid SNI, truncated/non-handshake, IP-literal SNI ignored, suffix `matches_bypass`.

2. **`bibavpn/src/local_client.rs`**
   - `resolve_domain_split_route`: DNS map / hostname bypass first (`sni_peek=false`); literal IP:443 SNI peek only when `sni_peek=true` after the SOCKS/HTTP success reply.
   - SOCKS `CONNECT` and HTTP `CONNECT`: send `socks5_reply_ok` / `reply_connect_ok` **before** TLS peek on IP:443; hostname/DNS-map Direct path unchanged (no peek).
   - `peek_tls_client_hello_record`: incremental `read` into one buffer so timeout/partial reads preserve bytes as `client_prefetch`.
   - `direct_bypass_relay` writes optional peeked prefix before `copy_bidirectional`.
   - Logs one `bibavpn_client` info line per direct bypass (host or recovered SNI).

3. **`apps/.../BibaVpnService.kt`**
   - Removed `applySplitTunnelDomainBypasses()` call from `startVpnTunnel` (no more `excludeRoute` for preset domains). Per-app `addDisallowedApplication` unchanged.

4. **`apps/bibavpn-desktop/ui/src/i18n.js`**
   - Updated `android_split_note` (ru/en): domain presets apply on all API levels via the tunnel client; per-app bypass still available.

5. **`apps/bibavpn-desktop/src-tauri/src/split_tunnel.rs`**
   - Comment only: Android domains flow to `split_bypass_domains`, not `excludeRoute`.

## Review fixes (reply-before-peek)

- IP:443 SNI peek runs only after SOCKS/HTTP CONNECT success reply so tun2socks sends ClientHello.
- Peek uses `read` accumulation; partial bytes are not dropped on timeout.

## Tests

```bash
cargo test -p bibavpn
```

All tests passed (171 unit + integration tests in this environment).

## Manual follow-up (not CI)

On a device with a bypass preset: HTTPS to a bypassed domain should egress with the device IP (not VPS), including under Private DNS/DoH; a non-bypass domain on a shared CDN IP should stay on the tunnel.
