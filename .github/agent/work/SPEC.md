# Spec

## Summary

TCP mux OPEN already tags each sid with a local epoch and removes the map entry only when that generation still owns it (`mux_remove_stream_if_epoch` / `mux_cleanup_should_remove` in `bibavpn/src/tcp_mux.rs`). Peer-driven CLOSE/RST does not: the server receive loop (`act.close || act.reset`) and the client downlink map both call `HashMap::remove(&sid)` with no epoch check. After a sid is reused, a delayed CLOSE/RST for generation N must not tear down generation N+1. Fix those map-removal call sites in one PR; do not put epoch on the mux record wire.

## In scope

- **Server receive loop** in `bridge_ws_tcp_mux_server`: on `act.close || act.reset`, stop calling `streams.lock().await.remove(&sid)`. Apply close/RST through `mux_remove_stream_if_epoch` (or a thin wrapper that calls it) using the generation this record belongs to:
  - If this record already looked up an `Open` entry for DATA, reuse that **captured** epoch for the close/RST (DATA is delivered first; close is applied after). A later generation of the same sid must not be removed.
  - If there was no DATA lookup, read `epoch()` under the streams lock and remove only when that value still matches (same predicate as `mux_cleanup_should_remove`).
- **Client downlink map** (`TcpMuxClientHandle::down`, today `HashMap<u32, mpsc::Sender<Vec<u8>>>`): store a per-sid epoch next to the sender (struct or `(u64, Sender)`). `open_stream` assigns a fresh epoch on every insert, including u32 sid wrap / reuse. Peer CLOSE/RST (~line 1280) and `mux_client_stream_bridge` teardown (`down.remove(&stream_id)` after sending CLOSE) must remove only when the mapped epoch is still that stream’s generation. Other sid-keyed `down.remove` paths in `open_stream` / DATA-send failure must not clobber a newer generation of the same sid.
- Reuse existing helpers (`mux_cleanup_should_remove`, `mux_remove_stream_if_epoch`). Add a client equivalent rather than duplicating ad-hoc `remove(&sid)` logic. Optional `bibavpn_mux` debug when a stale close/RST is ignored; do not log secrets.
- Unit test in `tcp_mux.rs` (same style as `stream_epoch_tests`): insert sid S at epoch 1, close it, reopen S at epoch 2, apply CLOSE/RST for epoch 1 — epoch 2 stays. Repeat the idea for the client map. Keep existing OPEN sid-reuse / epoch tests passing.

## Out of scope

- Carrying epoch (or any generation) in mux record headers or CLOSE/RST payload; no `PROTOCOL.md` / README / invite / CLI changes.
- Issues #61 (duplicate OPEN overwrite), #67 (fd leak / CLOSE-WAIT), #30 (window updates).
- UDP mux, REALITY, `--no-mux` TCP, flow control (`MUX_FLAG_WIN`).
- Changing sid allocation (skip-in-use on wrap) beyond epoch-safe map operations.
- New integration / WS / Docker / smoke harnesses.

## Files to change

- `bibavpn/src/tcp_mux.rs` — server CLOSE/RST removal; client `down` epoch; unit tests beside `stream_epoch_tests`.

## Tests

Add or extend `#[cfg(test)]` modules in `bibavpn/src/tcp_mux.rs` (prefer extending `stream_epoch_tests` plus a small client-map module). Cover:

1. Sid S opened at epoch 1, closed (epoch 1 removed), reopened at epoch 2; injecting CLOSE and RST for epoch 1 leaves epoch 2 mapped; CLOSE/RST for epoch 2 still removes it.
2. Combined `DATA|CLOSE` uses the epoch captured for that record’s DATA lookup, not a later mapped epoch.
3. Client `down` map: same reuse + stale CLOSE/RST; bridge-style teardown with the old epoch does not drop the new sender.
4. Existing tests still pass: `old_stream_cleanup_keeps_reused_sid_entry`, `duplicate_open_is_rejected_not_overwritten`, `read_loop_releases_stream_when_ws_queue_closed`, `read_loop_releases_stream_on_eof`.

Run:

```bash
cargo test -p bibavpn
```

No new harness. `biba` is not touched.

## Acceptance criteria

- A delayed CLOSE or RST for an old epoch does not remove a newer map entry for the same sid on the server streams map or the client `down` map.
- Peer CLOSE/RST and client stream teardown no longer use bare `remove(&sid)` for those maps.
- `cargo test -p bibavpn` passes, including existing SID-reuse / epoch tests.

## Non-goals

- Mux wire-format evolution, shared client/server epoch numbers, or PROTOCOL.md updates.
- Fixing sid wrap by avoiding reuse; this PR only makes reuse epoch-safe on CLOSE/RST.
- Performance work, stealth/DPI, or changes outside `tcp_mux.rs`.
