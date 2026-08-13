VERDICT: PASS

- Server `act.close || act.reset` no longer uses bare `streams.lock().await.remove(&sid)`; CLOSE/RST go through `mux_remove_stream_if_epoch` with the DATA-captured epoch when an `Open` lookup happened, otherwise the currently mapped `epoch()` under the streams lock.
- Client `down` stores `ClientDownEntry { epoch, tx }`; `open_stream` assigns a fresh epoch on every insert; peer CLOSE/RST, DATA-send failure, `open_stream` error paths, and `mux_client_stream_bridge` teardown all use `mux_remove_client_down_if_epoch` (same predicate as `mux_cleanup_should_remove`).
- No epoch (or generation) was added to mux record headers or CLOSE/RST payload; only `bibavpn/src/tcp_mux.rs` changed; no PROTOCOL/README/CLI/invite edits; no secrets.
- Named coverage is present beside `stream_epoch_tests` plus `client_down_epoch_tests`. Existing tests `old_stream_cleanup_keeps_reused_sid_entry`, `duplicate_open_is_rejected_not_overwritten`, `read_loop_releases_stream_when_ws_queue_closed`, and `read_loop_releases_stream_on_eof` remain and passed in `TEST.log` (`cargo test -p bibavpn`).
