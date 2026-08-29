# Implementation — transport phase 1

## Summary

Introduced `bibavpn::transport` with `OuterMsg` and `WsConn<S>` wrapping `WebSocketStream<S>`. Tunnel handshake, mux, bridge, REALITY, and AUTH paths now use `OuterMsg` / `WsConn` instead of `tungstenite::Message` / `WebSocketStream`. WebSocket construction (`client_async`, `from_partially_read`) remains at the edges and immediately wraps into `WsConn`.

## Tests

```bash
cargo test -p bibavpn
```

**Result:** all passed (171 lib unit tests + `reality_handshake`, `smoke`, `tunnel_integration`, `split_bypass_wiring`, server bin tests).

`cargo clippy -p bibavpn -- -D warnings` fails on pre-existing `biba` crate warnings (unused import, `manual_is_multiple_of`); no new clippy issues in `bibavpn` transport changes.
