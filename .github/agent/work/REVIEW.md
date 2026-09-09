VERDICT: PASS

- Client `log_client_transport_caps` is invoked once from `run_local_client` after the `ws_parallel` clamp; the duplicate `client.rs` call is gone. Snapshot fields match the spec (`mux_window_bytes`, post-clamp `ws_parallel`, `use_tcp_mux`, psk/reality presence, pad / `max_ws_binary` / dummy, crate version, download/upload window note). Existing desync/tls lines are unchanged.
- Server listen log passes `mux_window_mib`, pad / frame / dummy, and psk/reality booleans into `log_server_listen_caps`. No token, PSK material, invite, or PEM is formatted.
- Mux settle log is one `bibavpn_mux` info line when `Negotiation` first leaves `Pending` (WIN, timeout fallback, shutdown latch). `capability` / `parse_capability` / credit math / defaults / Android `ws_parallel` cap are untouched.
- Required snapshot tests are present (`mux_window_mib = 4`, `ws_parallel = 3`, PSK-no-REALITY and the inverse). `TEST.log` shows `cargo test -p bibavpn` **281 passed; 0 failed; 0 ignored** in debug, including `asymmetric_peers_transfer_multiple_configured_windows_both_directions`, negotiated-vs-legacy, and CLI `mux_window_cli_validates_*`.
- Local bench was skipped with a stated missing prerequisite (`python:3.12-slim` Docker image). No invented Mbps and no claim that the remote 200–257 Mbit/s report is fixed.
