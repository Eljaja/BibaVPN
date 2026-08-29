# Spec

## Summary

Introduce a transport-neutral outer duplex (`OuterMsg` + `WsConn`) and move every tunnel path off `WebSocketStream` / `tungstenite::Message`, with **no on-wire or CLI change**. WebSocket remains the only outer transport; this PR is the seam later gRPC-Web work will plug into.

Issue #39 is a six-phase wishlist. This spec is **phase 1 only**: a behavior-preserving refactor so a follow-up PR can add gRPC-Web without touching mux, REALITY, or handshake logic again.

## In scope

- Add `bibavpn/src/transport/{mod.rs,ws.rs}`:
  - `OuterMsg`: `Data(Bytes)`, `Ping(Bytes)`, `Pong(Bytes)`, `Close`. This is the subset of `tungstenite::Message` the tunnel actually uses.
  - `WsConn<S>` wrapping `WebSocketStream<S>`, implementing `Stream<Item = Result<OuterMsg, …>>` + `Sink<OuterMsg>` so existing `.split()`, `SinkExt::{send,feed,flush}`, and `StreamExt::next` call sites stay structurally the same.
  - Mapping: `Data` ↔ `Message::Binary`, `Ping`/`Pong`/`Close` likewise. Drop `Text` / other variants the same way call sites already ignore them (`_ => {}`).
  - `WsConn::from_websocket(WebSocketStream<S>)` used after `client_async` and `WebSocketStream::from_partially_read`.
- Refactor these modules to take `WsConn<S>` (or `&mut WsConn<S>`) instead of `WebSocketStream<S>`, and `OuterMsg` instead of `Message`:
  - Handshake / AUTH: `local_client.rs`, `ws_auth.rs`, `bibavpn/src/bin/server.rs`
  - REALITY: `reality.rs`
  - Long-lived sessions: `tcp_mux.rs`, `udp_mux.rs`, `ws_bridge.rs`
  - Accept: `incoming.rs` (`accept_websocket_or_camouflage` returns `Option<(WsConn<S>, WsHandshakeKind)>`)
- Keep generic bounds as today: `S: AsyncRead + AsyncWrite + Unpin + Send + 'static`.
- Keep ping/pong/close handling at the **same call sites** (do not silently auto-answer pings inside `WsConn` in this PR). Mux write queues that currently carry `Message` (`mpsc::channel::<Message>` in server mux/bridge/UDP) should carry `OuterMsg` instead. `MuxWriteCmd::Pong` and similar stay; only the last hop to the socket changes type.
- Export `pub mod transport` from `bibavpn/src/lib.rs`.
- One-line AGENTS.md module-table entry for `transport/` stating WS is the only implementation and mux/handshake speak `OuterMsg`, not `WebSocketStream`.

## Out of scope

Everything else from issue #39, deferred to later PRs:

- `h2` crate, `transport/grpc.rs`, gRPC-Web framing, grpc-web headers/path
- Server ALPN `["h2","http/1.1"]` and `incoming::accept_grpc_or_camouflage`
- Client/server `--transport`, `--grpc-path`, `InviteV1.transport`, `StartJson.transport`, `TransportMode`
- TLS profile ALPN changes (`tls_util.rs`, `tls_boring.rs`, `biba` ClientHello profiles)
- `stealth::build_grpcweb_request`, h2 SETTINGS / header-order mimicry
- New `bibavpn/tests/grpc_transport.rs`
- QUIC/HTTP-3, WebRTC, meek, replacing the custom mux with native h2 streams

## Files to change

**New**

- `bibavpn/src/transport/mod.rs` — `OuterMsg`, re-exports
- `bibavpn/src/transport/ws.rs` — `WsConn<S>`

**Modify (type swap only; no protocol/CLI behavior)**

- `bibavpn/src/lib.rs` — `pub mod transport`
- `bibavpn/src/incoming.rs` — wrap accepted WS in `WsConn`
- `bibavpn/src/ws_auth.rs`
- `bibavpn/src/local_client.rs` (including `ClientWs` alias)
- `bibavpn/src/reality.rs`
- `bibavpn/src/tcp_mux.rs`
- `bibavpn/src/udp_mux.rs`
- `bibavpn/src/ws_bridge.rs`
- `bibavpn/src/bin/server.rs`
- `bibavpn/tests/reality_handshake.rs` — server side of `accept_websocket_or_camouflage` now yields `WsConn`; test **client** may keep using `tokio_tungstenite` + `Message::Binary` as the peer
- `AGENTS.md` — crate module table row for `transport/`

**Do not change**

- `crypto_layer.rs`, `frame.rs`, `protocol.rs` (inner proto 3 unchanged)
- `tls_util.rs`, `tls_boring.rs`, `stealth.rs` (no ALPN / header mimicry)
- `invite_uri.rs`, `start_json_config.rs`, `client_policy.rs`, `bin/client.rs` (no `--transport`)
- `bibavpn/Cargo.toml` (no `h2` dependency)
- `PROTOCOL.md` (no wire-format change)

## Tests

Do not add a new integration harness.

- Add `#[cfg(test)]` in `bibavpn/src/transport/ws.rs` (tokio duplex or an in-process tungstenite pair):
  - `Data` round-trip equals the inner WS binary payload
  - `Ping` / `Pong` map to tungstenite ping/pong
  - peer `Close` surfaces as `OuterMsg::Close` (or stream end — pick one and test that)
- Update `incoming.rs` unit tests and `bibavpn/tests/reality_handshake.rs` if they name `WebSocketStream` on the accept return type. Existing WS client peers in those tests stay as-is.
- Required:

```bash
cargo test -p bibavpn
```

That must include unit tests plus `--test smoke`, `--test tunnel_integration`, `--test reality_handshake`, and `--test split_bypass_wiring`.

- Recommended before merge:

```bash
cargo clippy -p bibavpn -- -D warnings
```

## Acceptance criteria

- Outer on-wire behavior is unchanged: TLS + WebSocket upgrade, binary frames carrying proto-3 / REALITY / mux payloads, ping/pong/dummy/jitter all still work.
- No public CLI, invite, or JSON field is added or renamed.
- `tcp_mux`, `udp_mux`, `ws_bridge`, `reality`, `ws_auth`, and the client/server handshake helpers compile and run without naming `WebSocketStream` or `tungstenite::Message` (WS construction in `incoming.rs`, `local_client.rs`, `udp_mux.rs`, and `reality.rs` may still call `client_async` / `from_partially_read`, then immediately wrap).
- `cargo test -p bibavpn` is green.
- A follow-up can implement a second `OuterMsg` backend without further mux/handshake API churn.

## Non-goals

- No user-visible gRPC-Web / HTTP/2 transport in this PR.
- No change to proto-3, AUTH, MUX_OPEN, UDP mux records, or REALITY frame layout.
- No throughput work, no new tracing target, no auto-Pong inside `WsConn`.
- No type-erased `Box<dyn …>` outer connection unless a concrete generic `WsConn<S>` cannot compile; prefer the generic wrapper matching today’s `WebSocketStream<S>`.
