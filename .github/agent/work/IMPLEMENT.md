# Implementation

REALITY + v3 PSK transport keys now mix the X25519 shared secret from the REALITY handshake into `transport_keys` via `SessionCrypto::new_with_reality_dh`. Non-REALITY `SessionCrypto::new` is unchanged.

## Tests

All spec test commands passed in this environment:

- `cargo test -p bibavpn` — 189 tests (unit + integration)
- `cargo test -p bibavpn --test reality_handshake` — 4 tests

## Files changed

- `bibavpn/src/crypto_layer.rs` — optional DH in `transport_keys`; `new_with_reality_dh`; unit tests
- `bibavpn/src/udp_mux.rs` — retain REALITY DH; use `new_with_reality_dh` on REALITY path
- `bibavpn/src/bin/server.rs` — thread REALITY `session_key` into `server_handshake_v3_after_first_hello`
- `PROTOCOL.md` — REALITY + v3 key schedule and coordinated rollout
- `AGENTS.md` — one-liner on REALITY + v3 transport key mixing
