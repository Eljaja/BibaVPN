VERDICT: PASS

- `handle_http_peer` consults `should_bypass` after handshake and before mux/legacy; health check is still first and unchanged.
- HTTP `CONNECT` bypass replies `200 Connection Established` then `direct_bypass_relay` with `client_prefetch`; `ForwardHttp` bypass skips that 200 and writes `to_origin` first.
- `direct_bypass_relay` takes a prefetch slice (SOCKS passes `&[]`) and still uses `tcp_connect_host_protected`; only `bibavpn/src/local_client.rs` changed.
- Named tokio tests are present (CONNECT prefetch, non-bypass 502, ForwardHttp rewrite) with bypass-list mutex + cleanup; `cargo test -p bibavpn` passed (including `split_bypass_wiring`); no secrets or extra scope.
