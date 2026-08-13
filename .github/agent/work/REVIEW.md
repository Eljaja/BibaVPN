VERDICT: PASS

- Prefetch is a two-variant `WsBridgePrefetch` (`Ws` / `OpenedPayload`); `wait_open_status_or_payload` no longer re-wraps unpadded plaintext as a sealed `Message::Binary`.
- `bridge_ws_tcp_padded` writes `OpenedPayload` to TCP without a second `open_server_to_client`; empty payloads are skipped. Timeout still yields an empty prefetch; `OPEN_OK` / `OPEN_ERR` still resolve before `socks5_reply_ok`.
- Late v3 `OPEN_OK` is dropped after client decrypt+unpad; v3 `OPEN_ERR` fails the bridge. Legacy sealed-byte `is_open_ok` / `decode_open_err` checks were left in place.
- Diff is limited to `local_client.rs`, `ws_bridge.rs`, and a type-only empty prefetch in `server.rs`. Mux / UDP / REALITY / wire helpers / `SessionCrypto` were not changed. Test PSK is a placeholder.
- Required classify + handoff + late-`OPEN_OK` cases are present; `TEST.log` shows `cargo test -p bibavpn` passed (including `open_wait_tests` and `ws_bridge::tests`).
