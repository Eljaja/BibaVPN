VERDICT: PASS

- KDF matches SPEC: `transport_keys` keeps the PSK-only context; REALITY DH is appended as `u32be(32) || dh[32]` with the same `bibavpn.v3.c2s` / `bibavpn.v3.s2c` labels. `compute_mac` / `parse_ack` stay PSK-only.
- `SessionCrypto::new` signature is unchanged. `new_with_reality_dh` is used only on REALITY+v3: client UDP mux keeps the `reality_client_exchange_verify` secret; server threads `server_handshake_reality`’s `session_key` into `server_handshake_v3_after_first_hello`.
- Out-of-scope paths were left alone: non-REALITY `server_handshake_v3`, plaintext REALITY TCP mux (`bridge_ws_tcp_mux_server(..., None)`), `local_client.rs`, `biba/`, HELLO/ACK layout, CLI/invite.
- Required unit tests (`reality_dh_changes_keys`, `reality_dh_same_roundtrip`, `reality_dh_vs_psk_only_mismatch`) are present and passed; `cargo test -p bibavpn` (including `reality_handshake`) passed. `PROTOCOL.md` / `AGENTS.md` document the key-schedule change and coordinated rollout. No secrets in the diff.
