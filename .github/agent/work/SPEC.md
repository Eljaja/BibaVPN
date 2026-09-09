SIZE: SMALL
# Spec
## Summary

Three UDP-mux lifetime defects still exist in `bibavpn/src/udp_mux.rs` after top-level shutdown work (#41 / #67 / #127): client and server Ping tasks are stored in `_ping: JoinHandle` (dropping a Tokio `JoinHandle` detaches, it does not cancel); client pending `xid` entries are removed only on send failure, `UDP_REP`, or session drain — a SOCKS-side `timeout` in `local_client.rs` drops the oneshot receiver and leaves the map slot occupied up to `UDP_MUX_CLIENT_PENDING_CAP` (2048); server request workers are `tokio::spawn`ed untracked, so reader exit does not cancel resolve / pool lease / recv / jitter / WS send.

Fix session ownership and request cancellation in one PR. No wire-format, opcode, cap, or crypto changes. Do not treat this as a measured production RSS leak; write regressions for the audited mechanisms.

## In scope

1. **Session-owned children (A + C).** In `run_udp_mux_one_session` and `bridge_ws_udp_mux_server`, stop detaching Ping via `_ping`. Own every child (Ping and, on the server, per-request workers) in a `tokio::task::JoinSet` (or an equivalent abort-on-drop handle plus a bounded set). `JoinSet` drop must abort leftovers so cancelling the outer session future is enough — do not rely on a happy-path `abort()` after the loop. Reap finished server workers with `join_next` in the read loop so the set does not grow with historical requests. On any session exit (command-channel close, WS Close / read EOF, parse/crypto bail, write error, parent abort): stop admission, abort the set, drain with a short timeout (do not wait indefinitely for a final WS close/send). Do not hold the shared `Mutex<SplitSink>` across an unbounded send while expecting teardown to wait on it; abort the task that owns the send and let the guard drop.

2. **Client pending capacity (B).** Keep the 2048 map cap. Before every admission check, and on an idle `tokio::select!` tick (not only when the next `Forward` arrives), drop entries whose oneshot sender `is_closed()` (SOCKS worker timed out or cancelled). Do not add a wire cancel opcode. Prefer closed-oneshot reclaim over a delayed `Cancel { xid }` command so an old cancel cannot delete a newer request with the same `xid`. Keep occupied-`xid` collision handling (`udp_mux_xid_collision`) and current DNS snoop (`dns_expect` + `record_dns` only after a matching pending remove). Unknown/late `UDP_REP` stays a `trace` drop. Session drain still completes remaining oneshots once with `udp mux session ended`.

3. **Pooled sockets vs abandoned recv.** After `send_to`, a lease that times out, errors, or is cancelled must not return that fd to `UdpSocketPool` idle lists (late datagram must not be `recv_from` by a later lease). Recycle only when `recv_from` consumed a datagram, or the lease never sent. Ephemeral sockets drop with the worker. Optional pool idle baseline is the configured `--udp-socket-pool-size`, not zero process fds.

4. **Server outbound errors.** Resolve/bind/send failures that today only `error!(target: "bibavpn_udp", …)` still do not invent a new reply opcode. Client capacity must recover via (2) without a `UDP_REP`. Keep the existing empty timeout `UDP_REP` (`0.0.0.0:0`, empty payload) when `recv_timeout` fires and the session is still alive.

## Out of scope

- Proto-3 framing, `UDP_REQ` / `UDP_REP` layouts, PSK, AUTH, REALITY, TCP mux, JNI #83.
- Raising `UDP_MUX_CLIENT_PENDING_CAP` / `UDP_MUX_SERVER_MAX_INFLIGHT` or “fixing” leaks by growing maps.
- New transport, global runtime shutdown, process-wide task registries, metrics productization.
- Claiming or fixing unmeasured production RSS / CPU / “every disconnect leaks a socket”.
- Re-opening #41 / #67 top-level client/mux or TCP target-socket teardown.

## Files to change

- `bibavpn/src/udp_mux.rs` — Ping/worker ownership; client pending reclaim + idle tick; `UdpLease` discard-after-send-without-recv; server `JoinSet` spawn/reap/drain. Existing unit tests stay; add the cases below in this module (helpers may be `pub(crate)` / test-only).
- `bibavpn/src/local_client.rs` — no production change required if reclaim uses `oneshot::Sender::is_closed()` after the existing reply `timeout` drops `rx`. Touch only if a test hook must live next to the SOCKS UDP worker.
- Do not change `protocol.rs`, `crypto_layer.rs`, or invite/CLI.

## Tests

```bash
cargo test -p bibavpn
bash scripts/udp-socks-smoke.sh
```

(`udp-socks-smoke.sh` is the repo UDP SOCKS check from AGENTS.md. If the environment cannot run it, say so in the implementation report; do not invent a new harness.)

Add deterministic tests in `bibavpn/src/udp_mux.rs` (tokio duplex / mock sink, controlled time, no production load):

- **Ping ownership (client + server):** after session future completes or is aborted, the Ping task is gone while the runtime stays up. Cover command-channel close with a peer that still accepts writes, and parent-abort while Ping/send is in flight. A `Drop` counter or `JoinSet` emptiness is enough; do not require RSS.
- **Pending reclaim while WSS stays live:** mock peer never sends `UDP_REP`; drop/timeout 2048+ historical oneshots (short timeouts); idle tick must free slots without a further `Forward`; the next admit succeeds. Live 2048 still-held receivers still reject excess. Occupied-`xid` collision still errors. Closed-then-reuse of the same `xid` must not deliver a late `UDP_REP` to the new request.
- **Silent destination is not a leak:** server empty timeout `UDP_REP` still removes the pending entry when delivered.
- **Server workers:** fill inflight, close/abort the session during `recv_from` and during a blocked WS send; workers cancel, permits return, `JoinSet` drains. Repeat sessions. Run both `udp_socket_pool = None` and a small pool; a discarded in-flight lease must not hand a queued datagram to the next `lease()`.
- Keep existing pack/unpack, `max_ws_binary`, collision-map, DNS validation, and `bibavpn/tests/tunnel_integration.rs` coverage.

## Acceptance criteria

- Ping cannot outlive a completed or dropped UDP session on a live runtime (client and server error/cancel paths).
- Expired/cancelled requests release pending capacity on a live WSS, including during idle; the next valid request succeeds without reconnect.
- 2048 live outstanding requests remain capped; reclaim does not bypass the cap.
- Late/duplicate `UDP_REP`, `xid` reuse, and cancel races do not resolve the wrong request; DNS transaction/question validation is unchanged.
- Server session close/abort cancels and drains workers and releases permits / recv buffers / active leases under a stalled target and a stalled WS writer.
- Repeated teardown returns owned tasks to the session baseline; pool-enabled mode returns idle sockets to the configured pool size (not “zero fds”). Do not assert allocator high-water RSS.
- Successful PSK/DNS/UDP and existing timeout `UDP_REP` still work. TCP mux and process-wide runtime ownership are unchanged.
- Implementation notes list the deterministic regressions fixed and must not claim an unmeasured production RAM/CPU fix.

## Non-goals

- No new UDP error opcode, cancel frame, or cap bump.
- No TCP mux / JNI / global runtime rewrite.
- No production leak measurement or new e2e/fuzz harness.
- No PROTOCOL.md wire change.
