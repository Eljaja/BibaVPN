# Implementation summary

Hardened the `--camouflage-url` reverse-proxy path per SPEC.md.

## Review fix

- `slow_origin_hits_inner_timeout` and `forward_http_get_inner_respects_test_timeout`: accepted origin `TcpStream` is now held open with `pending().await` so the inner timeout triggers instead of an immediate RST from dropping the socket.

## Changes

### `bibavpn/src/incoming.rs`
- Added `allow_private: bool` to `CamouflageServeConfig` (default `false`).
- Added `sanitize_camouflage_request_target()` — accepts only origin-form `/path?query`, rejects absolute/authority/asterisk forms, traversal, encoded tricks, and control characters; caps rewritten target at 2048 bytes.
- Added `is_blocked_camouflage_origin()` / `is_blocked_camouflage_ipv4()` — deny loopback, RFC1918, link-local, CGNAT, unspecified, multicast, broadcast (IPv4 and IPv6, including IPv4-mapped).
- `forward_http_get` now sanitizes the request-target, checks resolved/connected peer addresses (unless `allow_private`), and caps origin copy at **1 MiB** and connect+read at **5 s**. Pre-byte failures return `Err` for the existing synthetic fallback; partial responses stop cleanly without a second HTTP response.
- Security rejects log on `bibavpn_security`; generic I/O errors remain on `bibavpn_camouflage`.
- Unit and tokio tests for sanitize, IP denylist, absolute-form rejection, origin-form rewrite, private-origin policy, huge/slow origin caps.

### `bibavpn/src/bin/server.rs`
- New flag `--camouflage-allow-private` (default off), passed into `CamouflageServeConfig`.

### Docs
- `README.md`, `AGENTS.md`, `PROTOCOL.md` — one-line mention of `--camouflage-allow-private`.

## Tests run

```bash
cargo test -p bibavpn          # 196 tests passed (slow_origin ~5s)
cargo clippy -p bibavpn -- -D warnings   # fails on pre-existing biba crate warnings (out of scope)
```

`bibavpn` sources lint clean; clippy failure is in dependency `biba` (`parrot.rs`, `parse.rs`), not in files touched by this spec.
