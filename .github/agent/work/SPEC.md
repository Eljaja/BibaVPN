# Spec

## Summary

Local HTTP proxy (`handle_http_peer` in `bibavpn/src/local_client.rs`) always opens a mux/legacy tunnel, so desktop system-proxy traffic (WinInet / macOS / GSettings HTTP CONNECT) ignores `domain_route::should_bypass`. SOCKS `CONNECT` already replies OK and calls `direct_bypass_relay`. Wire the same predicate and direct relay on HTTP `CONNECT` and on absolute-URI `GET`/`POST` (`HttpProxyHandshake::ForwardHttp`), including leftover/prefetch bytes so HTTPS ClientHello and rewritten origin requests are not dropped.

## In scope

- In `handle_http_peer`, after `http_proxy_handshake` succeeds, consult `crate::domain_route::should_bypass(&host)` **before** `ensure_tcp_mux_ready` / `open_legacy_biba_channel`.
- **HTTP `CONNECT`:** if bypass matches: `http_connect::reply_connect_ok`, then `direct_bypass_relay` (same order as SOCKS: success reply, then device-local TCP). Pass `client_prefetch` through to the origin (mux already forwards it; dropping it breaks eager TLS).
- **`ForwardHttp`:** if bypass matches: do **not** send `200 Connection Established`; connect direct and write `to_origin` first, then `copy_bidirectional` (same bytes the mux path would send as `tcp_uplink_prefix`).
- Extend `direct_bypass_relay` with a prefetch slice (`&[u8]`; empty for SOCKS). Keep using `outbound_protect::tcp_connect_host_protected` so Android `protect` still applies on the SOCKS bypass path.
- Leave `try_serve_health_check` first and unchanged (`GET /bibavpn-health` stays local).
- Empty bypass list remains a no-op (`should_bypass` already returns false).

## Out of scope

- Android TUN `excludeRoute` / issue #50.
- Desktop OS proxy-override / ignore-hosts “cache-only race”.
- SOCKS `CONNECT` / UDP ASSOCIATE behavior (already correct).
- `domain_route` match rules, DNS snoop, `set_bypass_domains`, start-JSON wiring.
- Wire format, server, UI, new CLI flags, camouflage HTTP on the TLS port.
- Changing mux/legacy paths for hosts that do **not** match bypass.

## Files to change

- `bibavpn/src/local_client.rs` — `direct_bypass_relay` prefetch argument; SOCKS caller passes `&[]`; `handle_http_peer` bypass branches for `Connect` and `ForwardHttp`; `#[cfg(test)]` tokio tests in this file (handler is private).
- Do not touch `bibavpn/src/http_connect.rs` unless a tiny helper is required to keep prefetch write in one place. Do not touch `biba/`.

## Tests

Run:

```bash
cargo test -p bibavpn
```

Add tokio tests in `bibavpn/src/local_client.rs` (do not add a new test binary; `split_bypass_wiring.rs` must stay the only integration test that owns start-JSON → global bypass list).

- Helper: bind a loopback origin that reads then writes a marker; `domain_route::set_bypass_domains(&["localhost".into()])` for the test body and `set_bypass_domains(&[])` in a `defer`-style cleanup. Serialize these tests with a module-level mutex so they do not race other lib tests on `GLOBAL_BYPASS`. Dummy `ClientCfg`: `use_tcp_mux = true`, unreachable `server_host`/`server_port` (mux would 502), `client_tls_config` with `insecure: true`, empty `TcpMuxSlot`, `SessionGuard` from a `watch` channel.
- **CONNECT bypass:** client sends `CONNECT localhost:<origin-port> HTTP/1.1\r\n\r\n` plus optional prefetch bytes; expect `HTTP/1.1 200 Connection Established`, origin receives prefetch, marker round-trips. Must succeed even though mux cannot connect.
- **CONNECT unknown host:** `CONNECT not-bypassed.example:<port>` (or any host that `should_bypass` rejects); expect `502` from `ensure_tcp_mux_ready` failure, origin never accepts a connection from this client.
- **ForwardHttp bypass:** `GET http://localhost:<origin-port>/path HTTP/1.1\r\nHost: localhost\r\n\r\n`; origin receives rewritten `GET /path HTTP/1.1` (not the absolute-URI form); no `200 Connection Established` on the client socket before origin bytes.

Existing `cargo test -p bibavpn --test split_bypass_wiring` and `domain_route` unit tests must still pass (no semantic change to matching).

Recommended before PR: `cargo clippy -p bibavpn -- -D warnings`.

## Acceptance criteria

- With split-tunnel domains installed (`set_bypass_domains` / start JSON `split_bypass_domains`), `curl -x http://127.0.0.1:<http-proxy> https://<bypass-domain>/` leaves via the device default route, same as SOCKS `CONNECT` to that host (`direct_bypass_relay` / `tcp_connect_host_protected`, not mux).
- HTTP `CONNECT` to a host that is not on the list (and not a DNS-mapped bypass IP) still goes through mux/legacy, unchanged.
- Absolute-URI `http://` proxy requests to a bypass host also go direct; health checks still return local `200` without a tunnel.
- `cargo test -p bibavpn` passes.

## Non-goals

- Making OS system-proxy ignore-lists the source of truth (in-process HTTP proxy must honor the same list as SOCKS).
- Bypass by raw IP unless `should_bypass` already would (DNS map); do not special-case HTTP.
- 502-before-200 for SOCKS; do not “fix” SOCKS reply-then-connect ordering in this PR.
- New e2e/docker/curl harnesses in CI.
