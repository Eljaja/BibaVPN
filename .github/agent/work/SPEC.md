# Spec

## Summary

`--camouflage-url` is served on the TLS port **before** tunnel AUTH. Today `forward_http_get` in `bibavpn/src/incoming.rs` copies the client request-target into the upstream request line as-is (so `GET http://other-host/…` is forwarded as an absolute URI) and then copies the origin response with no byte or time cap. The configured origin is not checked for loopback / private / link-local addresses.

This PR hardens that reverse-proxy path only: normalize or reject the request-target so the origin always sees origin-form `/path?query` under the configured host; refuse private/reserved origins unless `--camouflage-allow-private`; cap origin read bytes and time so a slow or huge origin cannot hang the pre-AUTH session.

## In scope

1. **Request-target sanitization** (in `forward_http_get`, before `TcpStream::connect`):
   - Accept only **origin-form** targets: a path that starts with exactly one `/` (not `//`).
   - Reject (do not connect, do not copy the raw target) if the target is absolute-form (`http://…`, `https://…`), authority-form (`//…`), asterisk-form (`*`), contains `\`, ASCII CR/LF/NUL/space, or a `..` path segment.
   - Also reject percent-encoded traversal / separator tricks in the path (before `?`): `%2e` / `%2E`, `%2f` / `%2F`, `%5c` / `%5C`.
   - On accept, rewrite to a single `/path?query` (query kept if present; empty path becomes `/`). Cap the rewritten target at 2048 bytes.
   - Upstream request line must use that rewritten target. `Host` stays the configured origin authority (already true). Do not forward other client headers.

2. **Private / reserved origin denylist** (default on):
   - After resolving the `--camouflage-url` host, refuse to connect if **every** resolved address is blocked, or if the connected `peer_addr()` is blocked.
   - Blocked IPv4: loopback (`127.0.0.0/8`), RFC1918 (`10/8`, `172.16/12`, `192.168/16`), link-local (`169.254/16`, includes metadata `169.254.169.254`), CGNAT (`100.64/10`), unspecified, multicast, broadcast.
   - Blocked IPv6: loopback (`::1`), unique local (`fc00::/7`), link-local (`fe80::/10`), unspecified, multicast. IPv4-mapped IPv6 uses the inner IPv4 check.
   - Opt-out: server flag `--camouflage-allow-private`. Pass it through `CamouflageServeConfig` (new `allow_private: bool`, default `false`).
   - Log rejects on `bibavpn_security` (no secrets). Generic origin I/O errors stay on `bibavpn_camouflage` as today.

3. **Origin copy caps** (constants in `incoming.rs`, not new CLI):
   - Max origin→client bytes: **1 MiB**.
   - Max origin connect+read time: **5 s** (inner timeout; the existing `--handshake-timeout-secs` wrapper is not enough, because it only drops the socket).
   - If the cap/timeout hits **before** any origin bytes were written to the client: return `Err` so `serve_camouflage_http` uses the existing reverse-proxy fallback (synthetic nginx-style index).
   - If some bytes were already written: stop copying, flush, close. Do not hang. Do not emit a second HTTP response.

4. **Docs**: mention `--camouflage-allow-private` next to `--camouflage-url` in `README.md` and `AGENTS.md` (CLI list). One line in `PROTOCOL.md` is enough (operator camouflage knobs, not wire format).

On sanitize / private-origin / pre-byte failure, keep today’s fallback in `serve_camouflage_http` (warn + synthetic index). Do not invent a new status code.

## Out of scope

- `--camouflage-dir` path traversal (issue #65).
- HTTPS origins (`http://` only, unchanged).
- New CLI for byte/time caps; extra client-header forwarding; CONNECT/TRACE; WebSocket over camouflage-url.
- Hostname allowlists (`metadata.google.internal` and friends) beyond the IP check after resolve/connect.
- Startup fatal error when `--camouflage-url` is a literal private IP (request-time reject + optional `WARN` is enough; local labs use `--camouflage-allow-private`).
- Changes to handshake timeout, AUTH, proto-3 wire, client, apps, Docker.

## Files to change

- `bibavpn/src/incoming.rs` — `CamouflageServeConfig`; sanitize helper; IP denylist helper; `forward_http_get` (rewrite path, check peer, cap copy); unit/tokio tests in the existing `#[cfg(test)]` module.
- `bibavpn/src/bin/server.rs` — `--camouflage-allow-private`; pass `allow_private` into `CamouflageServeConfig { … }`.
- `README.md`, `AGENTS.md`, and a one-line `PROTOCOL.md` operator note for the new flag.

Do not add a new crate, test binary, or harness. `biba` is untouched.

## Tests

Add tests next to the existing camouflage tests in `bibavpn/src/incoming.rs` (`#[cfg(test)]`). No new integration crate.

**Pure helpers**

- Sanitize: `/` and `/foo?x=1` accepted and rewritten; `http://127.0.0.1/foo`, `https://evil/x`, `//evil/x`, `*`, `\\foo`, `/a/../b`, `/a/%2e%2e/b`, `/a%2f../b`, and a target containing `\r\n` rejected (`None`).
- IP denylist: `127.0.0.1`, `10.0.0.1`, `192.168.1.1`, `169.254.169.254`, `::1`, `fe80::1` blocked; a public unicast like `8.8.8.8` / `2001:4860:4860::8888` allowed.

**Tokio (local `TcpListener` origin + `tokio::io::duplex` client)**

- Absolute-form `GET http://127.0.0.1/secret HTTP/1.1` against `reverse_proxy = http://127.0.0.1:<port>` with `allow_private = true`: origin must **not** receive a request line containing `http://`; client still gets a finished camouflage HTTP response (fallback or rewritten `/secret` — whichever the sanitize rule specifies; absolute-form is reject → fallback).
- Origin-form `GET /ok HTTP/1.1` with `allow_private = true`: origin sees `GET /ok HTTP/1.1` and `Host:` equal to the configured origin authority, not an absolute URI.
- Private origin with `allow_private = false`: listener on `127.0.0.1` must receive **no** accepted connection (or no HTTP bytes); client gets the reverse-proxy fallback, not a hang.
- Same origin with `allow_private = true` and origin-form `/`: request is forwarded.
- Huge origin: origin writes `> 1 MiB` after a small HTTP head; copy stops; function returns; client side does not block indefinitely.
- Slow origin: origin accepts and stalls; inner 5 s cap (test may pass a shorter timeout if the helper takes `Duration` for testability, or use `tokio::time::pause` — do not add a new harness). Session returns fallback or close, not a hang.

Existing camouflage / handshake-timeout tests in this module must still pass.

**Commands**

```bash
cargo test -p bibavpn
cargo clippy -p bibavpn -- -D warnings
```

(`-p biba` is not required.)

## Acceptance criteria

- `GET http://127.0.0.1/…` (or any absolute-form / `//…` / `..` / backslash target) is never copied into the upstream request line; the origin is not used as an open HTTP proxy.
- `--camouflage-url` pointing at loopback / RFC1918 / link-local / metadata (and the other reserved ranges listed above) is rejected by default; `--camouflage-allow-private` is required to reach them.
- A slow or huge origin is cut off by the inner byte/time cap; the TLS session still finishes with the usual camouflage fallback or a close, rather than hanging until the operator kills it.
- `cargo test -p bibavpn` passes.

## Non-goals

- Making camouflage a general-purpose reverse proxy (no header rewrite, no TLS origin, no streaming beyond the cap).
- Closing every SSRF class (file/unix/gopher, DNS rebinding beyond post-connect `peer_addr` check, cloud metadata hostnames).
- Changing default camouflage pages, nginx header fingerprint, or `--camouflage-dir`.
- Client, invite JSON, JNI/Tauri, or proto-3 changes.
