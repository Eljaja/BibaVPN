VERDICT: PASS

- `--reality-server-names` is enforced in `server_handshake_reality` via `is_server_name_allowed` / `validate_server_names` before HELLO, SERVER_HELLO, AUTH, and mux; reject uses existing `handle_one` REALITY `Err` logging/rate-limit.
- TLS SNI is taken from rustls after accept; HTTP `Host` is returned from `accept_websocket_or_camouflage`; matching is trim + decimal `:port` strip + `eq_ignore_ascii_case`; every presented name must match; missing both names fails closed when the list is non-empty.
- Omitted flag still defaults to `extract_sni(target)`; empty parse drops tokens, starts, accepts any name, and `WARN`s on `bibavpn_security`. Clap help, `PROTOCOL.md`, and `AGENTS.md` cover empty vs omitted. README does not list this flag, so it was correctly left alone.
- Named unit tests in `reality.rs` and the new `reality_handshake_rejects_non_listed_server_name` integration test are present. `cargo test -p bibavpn` in `TEST.log` passed (including `reality_handshake`: 5 tests). No extra product files, wire-format change, or secrets.
