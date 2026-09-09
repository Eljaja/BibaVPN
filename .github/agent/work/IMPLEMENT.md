# Implementation notes

**Note:** `bash scripts/udp-socks-smoke.sh` TCP leg passed; the UDP DNS step failed in this environment (`ModuleNotFoundError: No module named 'socks'`). `cargo test -p bibavpn` passed fully (301 tests).

## Summary

Fixed UDP-mux session lifetime defects in `bibavpn/src/udp_mux.rs` (no wire-format, cap, or crypto changes):

1. **Session-owned children** — Client and server Ping tasks plus server per-request workers live in a `JoinSet`; `drain_session_tasks` aborts and reaps on session exit. Server read loop calls `reap_finished_tasks` so the set does not grow with completed workers.
2. **Client pending reclaim** — `reclaim_closed_pending` drops map entries whose oneshot `Sender::is_closed()` before each admission check and on a 1 s idle `select!` tick (50 ms in unit tests). The 2048 cap is unchanged; SOCKS timeouts in `local_client.rs` need no production change.
3. **Pooled socket safety** — `UdpLease::recycle_on_drop` is cleared after `send_to` without a matching `recv_from`; abandoned in-flight leases are not returned to `UdpSocketPool` idle lists.
4. **Server outbound errors** — Unchanged: resolve/bind/send failures log only; empty timeout `UDP_REP` still sent when `recv_timeout` fires.

This addresses detached Ping tasks, stale pending `xid` slots on a live WSS, and untracked server workers — not unmeasured production RSS/CPU.

## Tests

```bash
cargo test -p bibavpn          # passed (301 tests, incl. new udp_mux::tests)
bash scripts/udp-socks-smoke.sh  # TCP OK; UDP step needs PySocks in this CI image
```

New / strengthened deterministic regressions in `bibavpn/src/udp_mux.rs`:

- **Ping ownership (client + server):** `PING_TASKS_ALIVE` counter; cmd-channel close with live peer; abort while `BLOCK_WS_SEND` holds Ping/worker WS send
- **Pending reclaim on live WSS:** `client_session_reclaims_on_idle_tick` fills 2048 slots with live receivers, drops them, idle tick frees capacity without another `Forward`
- **Cap / xid through session driver:** `client_session_pending_cap_rejects_excess_forward`, `client_session_xid_collision_through_driver`, `client_session_late_rep_after_reclaim_not_delivered_to_reuse`
- **Server workers:** fill `UDP_MUX_SERVER_MAX_INFLIGHT`, abort during `recv_from` and blocked WS send; repeat sessions; pool and no-pool modes; semaphore permits and `JoinSet` drain via test hooks
- **Pool discard:** `discarded_pool_lease_does_not_recv_queued_datagram_on_next_lease` (real UDP echo; next lease cannot inherit queued reply)
- Empty timeout `UDP_REP` end-to-end via duplex WSS (existing test retained)

## Files changed

- `bibavpn/src/udp_mux.rs` — production fixes, `#[cfg(test)]` hooks, and tests only (`local_client.rs` untouched)
