# Spec

## Summary

On the **REALITY + v3 PSK** path, mix the X25519 shared secret already returned by `reality_client_exchange_verify` / `server_handshake_reality` into `crypto_layer::transport_keys` so ChaCha20-Poly1305 session keys are not recoverable from PSK + public HELLO/ACK randoms alone.

Today those 32-byte DH secrets are discarded (`_session_key` in `bibavpn/src/bin/server.rs` after REALITY AUTH, and the unused return of `reality_client_exchange_verify` in `bibavpn/src/udp_mux.rs`). `SessionCrypto::new` then derives `bibavpn.v3.c2s` / `bibavpn.v3.s2c` from PSK + proto-domain + `client_random` + `server_random` only. Those randoms are on the wire, so a later PSK leak decrypts captured REALITY+v3 sessions.

This PR is a **coordinated client/server key-schedule change** for REALITY+v3 only. HELLO/ACK bytes and REALITY handshake frames stay the same (`REALITY_VERSION` remains 2). Mixed-version peers fail at the first sealed v3 frame (AUTH), not at HELLO/ACK. The non-REALITY PSK path must keep **byte-identical** transport keys.

## In scope

1. **KDF (private `transport_keys` in `bibavpn/src/crypto_layer.rs`)**
   - Keep the current context when no REALITY DH is supplied (non-REALITY keys unchanged):
     `u32be(psk.len) || psk || u32be(domain.len) || domain || client_random[32] || server_random[32]`
     then `blake3::derive_key("bibavpn.v3.c2s" | "bibavpn.v3.s2c", ctx)`.
   - When a REALITY shared secret is supplied, append `u32be(32) || dh[32]` to that same context. Do **not** invent new KDF labels. Do **not** fold DH into `bibavpn.v3.mac.psk` / ACK MAC (`compute_mac` / `parse_ack` stay PSK-only).
   - DH input is the existing 32-byte X25519 shared secret from the REALITY handshake (already copied into `session_key` in `reality.rs`). Do not re-run DH.

2. **`SessionCrypto` API**
   - Keep `SessionCrypto::new(psk, domain, client_random, server_random, decoy_max)` as the PSK-only constructor (callers and keys unchanged).
   - Add one constructor used only on REALITY+v3, e.g. `SessionCrypto::new_with_reality_dh(..., reality_dh: &[u8; 32])`, implemented by passing `Some(dh)` into `transport_keys`.

3. **Thread DH into the REALITY+v3 SessionCrypto sites (both ends must pass the same secret)**
   - **Client UDP mux** (`bibavpn/src/udp_mux.rs`): capture the `[u8; 32]` from `reality_client_exchange_verify` instead of discarding it; pass it to `new_with_reality_dh` when REALITY ran. If `reality_public_key` is absent, keep `SessionCrypto::new`.
   - **Server** (`bibavpn/src/bin/server.rs`): keep the `Ok(session_key)` from `server_handshake_reality` (today `_session_key`). Pass it into `server_handshake_v3_after_first_hello` and construct crypto with `new_with_reality_dh`. The plaintext `MUX_OPEN` branch after REALITY is unchanged.

4. **Docs (rollout)**
   - `PROTOCOL.md`: under REALITY + v3 PSK (UDP mux / HELLO after REALITY), state that `c2s`/`s2c` also bind the REALITY X25519 shared secret; HELLO/ACK MAC does not; client and server must upgrade together; mixed versions fail at sealed AUTH.
   - `AGENTS.md`: one sentence in the PSK / REALITY notes that REALITY+v3 mixes the ephemeral DH into transport keys (not ACK MAC). No CLI flags.

## Out of scope

- Wrapping **REALITY TCP mux** in `SessionCrypto` (plaintext `MUX_OPEN` after REALITY AUTH, `spawn_tcp_mux_client(..., None)` / `bridge_ws_tcp_mux_server(..., None)`). That path has no PSK-keyed data channel today; encrypting it is a larger wire change.
- Changing REALITY HELLO / SERVER_HELLO / client AUTH layout or `REALITY_VERSION`.
- Mixing DH into ACK MAC, AUTH token, or invite encoding.
- Non-REALITY v3 (`one_try_wss_session`, `server_handshake_v3`).
- New CLI flags, invite fields, or stealth/TLS changes.
- Replacing X25519, adding double-ratchet / rekey, or encrypting the discarded TCP-mux `_session_key` without v3 HELLO.

## Files to change

- `bibavpn/src/crypto_layer.rs` — optional DH in `transport_keys`; new constructor; unit tests.
- `bibavpn/src/udp_mux.rs` — keep REALITY DH; `SessionCrypto::new_with_reality_dh` on that path.
- `bibavpn/src/bin/server.rs` — thread REALITY `session_key` into `server_handshake_v3_after_first_hello`.
- `PROTOCOL.md` — REALITY+v3 key schedule + coordinated rollout.
- `AGENTS.md` — matching one-liner.
- `bibavpn/tests/tunnel_integration.rs` — only if `SessionCrypto::new` signature changes (prefer not to). Existing `session()` helper stays PSK-only.

Do not touch `biba/`. `local_client.rs` REALITY TCP mux may keep discarding `_session_key` (out of scope).

## Tests

Run from repo root:

```bash
cargo test -p bibavpn
cargo test -p bibavpn --test reality_handshake
```

Add unit tests in `bibavpn/src/crypto_layer.rs` (`#[cfg(test)]`), same seal/open style as `v3_domain_changes_keys`:

- **DH changes keys:** same PSK, domain, and HELLO/ACK randoms; two different `reality_dh` values; ciphertext from one `new_with_reality_dh` must fail `open_*` on the other.
- **Same DH roundtrips:** identical inputs including DH; `seal_client_to_server` / `open_client_to_server` (and s2c) succeed.
- **DH vs PSK-only:** `new_with_reality_dh` ciphertext must not open on `SessionCrypto::new` with the same PSK/domain/randoms (and the reverse).
- Existing `SessionCrypto::new` tests must keep passing (non-REALITY schedule unchanged).

`reality_handshake.rs` stays handshake-only (shared-secret equality). Do not add a new live-server harness. `cargo test -p bibavpn` already runs `tests/tunnel_integration.rs` and `tests/smoke.rs`.

## Acceptance criteria

- With REALITY+v3, transport keys depend on the ephemeral DH: same PSK + same public randoms + different DH secrets produce different AEAD keys (unit test above).
- Client and server REALITY+v3 UDP/HELLO paths both pass the handshake DH into `SessionCrypto`; omitting it on one side cannot decrypt.
- Non-REALITY `SessionCrypto::new` keys are unchanged; existing v3 unit/integration tests pass.
- `cargo test -p bibavpn` passes, including `--test reality_handshake` (TLS+WSS REALITY handshake).
- `PROTOCOL.md` (and the `AGENTS.md` one-liner) document the key-schedule change and that client and server must ship together on the REALITY+v3 path.

## Non-goals

- Forward secrecy for plaintext REALITY TCP mux, or for the outer TLS layer.
- Protection if the REALITY long-term private key is stolen (server DH is static; FS here is vs **PSK** compromise of captured v3 ciphertext).
- Backward compatibility with old REALITY+v3 peers (this is an intentional break on that path only).
- Performance work, new opcodes, or a second inner crypto version byte.
