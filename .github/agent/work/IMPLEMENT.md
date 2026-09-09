# Implementation notes (#129 slice 1)

## Summary

Added structured **effective-config** logging on client (`run_local_client`) and server (listen), plus one **per-session** `bibavpn_mux` line when mux credit negotiation first settles (`Credit` or `Legacy`). No wire/default/Android-cap changes.

## Code changes

| File | Change |
|------|--------|
| `bibavpn/src/transport_capabilities.rs` | `EffectiveConfigSnapshot` / `ServerEffectiveConfigSnapshot`; mux/pad/frame/dummy/psk/reality/version fields in client and server helpers; unit tests |
| `bibavpn/src/local_client.rs` | Call `log_client_transport_caps` once after `ws_parallel` clamp |
| `bibavpn/src/bin/client.rs` | Removed duplicate `log_client_transport_caps` call (now only via `run_local_client`) |
| `bibavpn/src/bin/server.rs` | Pass mux/pad/frame/dummy/psk/reality into `log_server_listen_caps` |
| `bibavpn/src/tcp_mux_flow.rs` | One `bibavpn_mux` info line on first negotiation settle (WIN, timeout fallback, shutdown latch); debug-aware timeout for multi-window duplex test |

## Tests

```bash
cargo test -p bibavpn
```

- **281 / 281** unit/integration tests pass in **debug** on this runner (see `TEST.log` tail below).
- `tcp_mux::flow::tests::asymmetric_peers_transfer_multiple_configured_windows_both_directions` uses a 60 s debug timeout (10 s in release) because encrypted padding/decoy paths move ~20 MiB per case and exceed 10 s unoptimized.
- New snapshot tests: `transport_capabilities::tests::{client_effective_config_snapshot_*, server_effective_config_snapshot_fields}`.

### `cargo test -p bibavpn` (debug, tail)

```
test tcp_mux::flow::tests::asymmetric_peers_transfer_multiple_configured_windows_both_directions ... ok
test result: ok. 281 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 34.77s
```

## Local throughput bench (optional)

**Skipped** — `scripts/local-throughput-bench.py` requires a cached `python:3.12-slim` Docker image (`docker pull python:3.12-slim` not run here). No loopback Mbps recorded.

Planned matrix (not executed): `mux-win-1` (default), `mux-win-4` (`--client-arg=--mux-window-mib --client-arg=4`), `no-mux` (`--client-arg=--no-mux`), each `--repeats 3`, download GET, 1 stream — **local fixture only**; does not verify or fix the remote 200–257 Mbit/s report.

## Log fields (no secrets)

**Client** (`bibavpn_client`, once per `run_local_client`): `mux_window_bytes`, `ws_parallel` (post-clamp), `use_tcp_mux`, `psk`, `reality`, `max_ws_binary`, `max_pad`, `dummy_interval_secs`, `version`, plus download/upload window note.

**Server** (`bibavpn_server`, once at listen): matching server-side window/pad/frame/dummy/psk/reality/version fields.

**Mux session** (`bibavpn_mux`, once per outer WSS): `credit_negotiated`, `local_receive_window_bytes`, `peer_window_bytes` (`0` on legacy).
