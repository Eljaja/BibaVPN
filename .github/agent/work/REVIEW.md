VERDICT: PASS

- Phase-1 seam is in place: `OuterMsg` (`Data`/`Ping`/`Pong`/`Close`) and generic `WsConn<S>` as `Stream`+`Sink`, with `from_websocket` after `client_async` / `from_partially_read`. Text/other tungstenite variants are dropped in `WsConn`; pings are not auto-answered there.
- Handshake/AUTH, REALITY, mux, bridge, accept, and `ClientWs` were type-swapped to `WsConn`/`OuterMsg`. Mux write queues carry `OuterMsg`; `MuxWriteCmd::Pong` remains. Construction still lives only at the allowed edges (`incoming.rs`, `local_client.rs`, `udp_mux.rs`, `reality.rs`).
- Scope stayed inside the spec: no `h2`/`grpc`, no CLI/invite/JSON/`PROTOCOL.md`/`Cargo.toml`/inner-proto/TLS-ALPN edits, no secrets. `pub mod transport` and the AGENTS.md module-table row are present.
- Named `transport/ws.rs` unit tests cover Data round-trip, Ping/Pong mapping, and peer Close. `cargo test -p bibavpn` in TEST.log is green (171 lib tests including those, plus `smoke`, `tunnel_integration`, `reality_handshake`, `split_bypass_wiring`).
