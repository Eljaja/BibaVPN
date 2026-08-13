# Spec

## Summary

On the legacy `--no-mux` path, `wait_open_status_or_payload` in `local_client.rs` decrypts the first post-`OPEN` server binary to classify `OPEN_OK` / `OPEN_ERR` / payload. When the frame is payload, it currently re-injects the **unpadded plaintext** as `Message::Binary`. `bridge_ws_tcp_padded` then treats that as a still-sealed WS binary and calls `open_server_to_client` again. Decrypt fails and the tunnel dies.

`ChaHalf::open` reads the nonce from the wire (it does not consume a receive counter), so returning the **original sealed** bytes would decrypt successfully a second time — but the issue forbids a second AEAD open. The shippable fix is: decrypt once to classify; if the inner is TCP payload, hand the already-opened (unpadded) bytes to the bridge as a distinct prefetch item that is written to TCP **without** another `open_*`.

Happy path (server sends `OPEN_OK` then data) stays: prefetch is empty, later frames take the normal sealed path (one open each).

## In scope

- Change `wait_open_status_or_payload` so a non-status first binary is **not** wrapped as a sealed `Message::Binary`.
- Introduce a small prefetch type (in `ws_bridge.rs`, used by `local_client.rs`) with two variants, for example:
  - `Ws(Message)` — untouched WS control / non-binary frames (today’s `other => return Ok(vec![other])`).
  - `OpenedPayload(Vec<u8>)` — already `open_server_to_client` + `read_padded_frame_into`; write to the local TCP socket as-is.
- Update `bridge_ws_tcp_padded` to drain that type: `OpenedPayload` → `tcp_write.write_all` (skip empty); `Ws` → existing match.
- After a **normal** sealed downlink decrypt on `TunnelEnd::Client`, skip leftover v3 `OPEN_OK` (`is_v3_open_ok`) and fail on v3 `OPEN_ERR` (`decode_v3_open_err`) so a late status frame after `OPEN_STATUS_WAIT` (350 ms) is not written to SOCKS as `[0x10]`.
- Keep `OPEN_OK` → empty prefetch and `OPEN_ERR` → `bail!` **before** `socks5_reply_ok` (same as today).
- Keep the timeout-empty prefetch behavior (`Err(_) => Vec::new()`).
- Unit tests for classify + “open once” handoff (see Tests).

## Out of scope

- Mux (`tcp_mux.rs`), UDP mux, REALITY, `--ws-parallel`.
- Server `wait_first_channel` / issue #77, mux CLOSE epoch / issue #76.
- Changing proto-3 wire, `OPEN` / `OPEN_OK` / `OPEN_ERR` opcodes, or `PROTOCOL.md`.
- Removing the unused legacy `is_open_ok` / `decode_open_err` checks on **sealed** bytes in the bridge.
- Rewinding or changing `SessionCrypto` / `ChaHalf` nonce behavior.
- New e2e / Docker / SOCKS smoke harnesses; live `--no-mux` lab runs.
- Docs, CLI flags, invite JSON, `biba` crate.

## Files to change

- `bibavpn/src/ws_bridge.rs` — prefetch item type; `bridge_ws_tcp_padded` signature and uplink loop; after client `open_server_to_client` + unpad, ignore v3 `OPEN_OK` and bail on v3 `OPEN_ERR`.
- `bibavpn/src/local_client.rs` — `wait_open_status_or_payload` / `open_legacy_biba_channel` return type; three `bridge_ws_tcp_padded` call sites; extract a sync classify helper (same file) for tests.
- `bibavpn/src/bin/server.rs` — pass `Vec::new()` (or equivalent empty prefetch) with the new type only; no server behavior change.
- `bibavpn/src/lib.rs` — only if the prefetch type must be re-exported for the server bin (prefer `ws_bridge::…` and avoid a new public surface).

Do not touch `protocol.rs` wire helpers unless a test imports existing `is_v3_open_ok` / `decode_v3_open_err` / `encode_v3_open_*`.

## Tests

Add `#[cfg(test)]` coverage next to the classify helper in `bibavpn/src/local_client.rs` (and a thin bridge helper test in `ws_bridge.rs` only if classify is not enough to lock the handoff). Use existing `SessionCrypto` + `write_padded_frame` / `read_padded_frame_into` like `bibavpn/tests/tunnel_integration.rs`. No new test binary.

Required cases:

1. **`OPEN_OK` then data (classify):** sealed `encode_v3_open_ok()` opens to `OpenWait::Ok` (empty prefetch). A following sealed TCP chunk opens once to `OpenWait::Payload` equal to the original bytes. The payload path must not call `open_server_to_client` a second time.
2. **Data with no `OPEN_OK`:** first sealed frame is payload (e.g. `b"early"`). Classify returns `OpenedPayload` / `Payload` with those bytes. Feeding that plaintext to `open_server_to_client` must fail (documents the current bug). The handoff uses the opened bytes only.
3. **`OPEN_ERR`:** sealed `encode_v3_open_err(...)` classifies as error; wait helper still bails with the remote reason.
4. **Late `OPEN_OK` on the sealed bridge path:** after decrypt + unpad, `is_v3_open_ok` is dropped (no TCP write), so a timeout-race status frame does not leak `0x10` to the SOCKS client.

Run:

```bash
cargo test -p bibavpn
```

Do not add `-p biba`. Optional before PR (not required for this spec): `cargo clippy -p bibavpn -- -D warnings`.

## Acceptance criteria

- `--no-mux` still moves application bytes when the first server frame after client `OPEN` is payload rather than `OPEN_OK`.
- Each server→client frame is AEAD-opened at most once on the client. Prefetch of early payload does not trigger a second `open_server_to_client`.
- `OPEN_OK` is consumed (not written to SOCKS). `OPEN_ERR` still fails the legacy open **before** `socks5_reply_ok`.
- A late v3 `OPEN_OK` that arrives after `OPEN_STATUS_WAIT` is not written to the local TCP socket.
- Mux / default client path is unchanged.
- `cargo test -p bibavpn` passes.

## Non-goals

- Making `--no-mux` the default or improving its performance.
- Pipelining / reordering guarantees beyond “first non-status binary is payload and must survive.”
- Changing `OPEN_STATUS_WAIT`, padding, dummy frames, or server send order (`OPEN_OK` then `bridge_ws_tcp_padded`).
- Full GREASE / DPI / stealth work.
- Public API stability for the prefetch type beyond compiling the server and client bins.
