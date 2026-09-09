SIZE: SMALL
# Spec
## Summary

Ship the approved first slice of #129: one structured **effective-config** log on client and server (including JSON/JNI/Tauri starts), plus one **per-session** mux line after WIN credit negotiation vs legacy fallback. Then run the existing local HTTPS-vs-SOCKS fixture with window 1 vs 4 on the **client** (download receive side) and mux vs `--no-mux`. Do not raise defaults, do not change the WIN wire, and do not claim the remote 200–257 Mbit/s report is fixed.

## In scope

1. **Client effective-config log (once per `run_local_client`).** Emit a single `info` line under `bibavpn_client` after options are fully resolved (CLI clamp, invite/JSON merge). Call it from `run_local_client` so JNI, FFI, and Tauri see the same line; if `log_client_transport_caps` already logs on the CLI binary, fold the mux fields into that helper and invoke it **only** from `run_local_client` (remove the extra `client.rs` call to avoid a double line).

   Structured fields (no secrets):
   - `mux_window_bytes` — local advertised receive window (`MuxWindow::bytes()`, default 1 MiB)
   - `ws_parallel` — value after `.max(1).min(4)` (this is the post-override count; Android already rewrites JSON to 1 in `capWsParallelForUdpMux` before `nativeStart`)
   - `use_tcp_mux` — false when `--no-mux` / JSON `use_tcp_mux: false`
   - `psk` — boolean presence only
   - `reality` — boolean presence only (`reality_target` + public key configured)
   - `max_ws_binary`, `max_pad`, `dummy_interval_secs`
   - crate version via `env!("CARGO_PKG_VERSION")` (not used today; add it here)
   - static message text that download credit is limited by the **client** advertised window and upload by the **server** advertised window

2. **Server effective-config log (once at listen).** Extend `log_server_listen_caps` (or an adjacent `bibavpn_server` `info` line next to it) with the same window/pad/frame/dummy fields, `psk` / `reality` presence booleans, crate version, and the same download/upload window note. Do not log token, PSK material, invite, or cert PEM.

3. **Mux session credit-mode log (once per outer WSS).** When `Negotiation` first leaves `Pending` (`Credit(window)` or `Legacy`) in `tcp_mux_flow.rs`, emit one `info` line under `bibavpn_mux`: `credit_negotiated` (bool), `local_receive_window_bytes`, `peer_window_bytes` (omit or `0` on legacy). Hook the existing `send_if_modified` / `send_replace` sites (capability WIN, timeout fallback, shutdown latch) so mixed-version sessions are visible. No per-frame or per-stream production logs.

4. **Documented local matrix (existing harness only).** Using `scripts/local-throughput-bench.py` (wrapper `scripts/wsl-local-bench.sh`), same payload, `--repeats` ≥ 3, keep raw JSONL. One variable at a time:
   - default mux, client `--mux-window-mib 1` (implicit default)
   - mux, `--client-arg=--mux-window-mib --client-arg=4` (download receive window)
   - `--client-arg=--no-mux`
   Record SHA/build of the binaries used, units (Mbps from the script), direction = download GET, stream count = 1. If Docker / curl / openssl / a **Linux** server binary are missing, skip the fixture and say so; do not invent Mbps. One extra run with `--client-arg=--log-level --client-arg=info` is enough to capture the new lines (the script defaults both sides to `--log-level error`).

## Out of scope

- Raising the default `MuxWindow` (stay at 1 MiB) or widening the 1–4 CLI/JSON range.
- Credit-stall counters, writer/AEAD profiling, Prometheus / product metrics.
- `--server-arg` on the bench, upload POST/PUT, multi-curl concurrency, tc/netem RTT, or a new bench crate.
- Changing `capability` / `parse_capability` / `BFC1` wire, proto 3, REALITY AUTH, or `crypto_layer.rs`.
- Removing or changing Android `capWsParallelForUdpMux` (keep the existing rewrite log).
- Striping one stream across multiple WSS; claiming the remote 200–257 Mbit/s ceiling is explained or fixed from loopback numbers.

## Files to change

- `bibavpn/src/transport_capabilities.rs` — add mux/window/pad fields (and crate version) to the client helper and `log_server_listen_caps`; keep existing desync/tls lines.
- `bibavpn/src/local_client.rs` — call the client helper once from `run_local_client` after `ws_parallel` clamp.
- `bibavpn/src/bin/client.rs` — drop the now-duplicate `log_client_transport_caps` call if it moves into `run_local_client`.
- `bibavpn/src/bin/server.rs` — pass `mux_window_mib`, pad / `max_ws_binary` / dummy, and psk/reality presence into the listen-caps log (values already on `Args`).
- `bibavpn/src/tcp_mux_flow.rs` — one `bibavpn_mux` info line when negotiation first settles; do not touch credit math, DATA chunking, or writer batching.

Do not edit `apps/bibavpn-desktop/.../BibaVpnService.kt`, `protocol.rs`, or `scripts/local-throughput-bench.py` in this PR unless a one-line comment in the bench docstring is needed to point at `--client-arg=--mux-window-mib`.

## Tests

```bash
cargo test -p bibavpn
```

Required existing coverage (must still pass): `tcp_mux_flow` negotiated vs legacy (`new_peers_negotiate_before_first_open`, `first_stream_negotiates_and_old_server_fallback_is_latched`), slow-reader / duplex / cancellation tests in that module, CLI `mux_window_cli_validates_*` in `client.rs` / `server.rs`, JSON `mux_window_mib` cases in `start_json_config.rs`.

Add a small unit test next to `log_client_transport_caps` / `log_server_listen_caps` that builds options with `mux_window_mib = 4`, `ws_parallel = 3`, `use_tcp_mux = true`, PSK set, no REALITY (and the inverse: REALITY set, no PSK) and asserts the helper’s field snapshot: `mux_window_bytes == 4 * 1024 * 1024`, `ws_parallel == 3`, booleans correct, and that token/PSK strings are not formatted into the message. Extract a `pub(crate)` snapshot struct if that is cleaner than asserting via logs.

Optional evidence (not a CI gate):

```bash
cargo build --release -p bibavpn --bin bibavpn-server --bin bibavpn-client
python3 scripts/test-local-throughput-bench.py
python3 scripts/local-throughput-bench.py --repeats 3 --label mux-win-1
python3 scripts/local-throughput-bench.py --repeats 3 --label mux-win-4 --client-arg=--mux-window-mib --client-arg=4
python3 scripts/local-throughput-bench.py --repeats 3 --label no-mux --client-arg=--no-mux
```

## Acceptance criteria

- Client start (CLI **and** `run_local_client` JSON/JNI/Tauri path) logs one line with effective `mux_window_bytes`, post-clamp `ws_parallel`, `use_tcp_mux`, psk/reality **presence**, pad / `max_ws_binary` / dummy, and crate version. Server listen logs the matching server-side window and presence flags.
- After mux WIN exchange or legacy timeout, exactly one `bibavpn_mux` line per outer session states `credit_negotiated` and the local/peer windows. Late WIN after a legacy latch still does not upgrade (existing test).
- Logs never include token, PSK, invite URI, or PEM.
- Defaults, Android `ws_parallel` cap, and WIN/capability bytes are unchanged.
- `cargo test -p bibavpn` passes.
- Bench JSONL is attached or the PR states which prerequisites were missing. Loopback Mbps must be labeled **local fixture only** and must not be reported as fixing the remote ceiling.

## Non-goals

- Do not treat numerical resemblance of 1 MiB / ~33–42 ms to 200–257 Mbit/s as attribution.
- Do not add hot-path credit timers or change memory caps / slow-consumer isolation.
- Do not run uncontrolled load against a public or production endpoint.
- Do not invent a new test harness.
