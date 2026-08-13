# Spec

## Summary

After v3 AUTH succeeds, `run_session_after_v3_handshake` calls `wait_first_channel` with no deadline. A peer that keeps the WebSocket open and only sends pings or valid AEAD frames that are not `OPEN` / `MUX_OPEN` / `UDP_MUX_OPEN` can hold a `--max-concurrent-sessions` permit and `SessionGuard` until it disconnects.

Bound that wait with the existing `--handshake-timeout-secs` (default 15s, one full phase, same as HELLO…AUTH). Count successfully decrypted non-open binary frames against the existing `PreAuthBudget`. On timeout, increment `handshake_timeouts_total`, `auth.record_failure` for the peer IP, and return an error so the permit is released. A timely `OPEN` / `MUX_OPEN` / `UDP_MUX_OPEN` still proceeds unchanged.

## In scope

- Wrap `wait_first_channel` in `tokio::time::timeout` using `params.handshake_timeout` (`--handshake-timeout-secs`, minimum 1s as today). Fresh full duration for this phase, not leftover time from AUTH.
- Both callers of `run_session_after_v3_handshake` (plain v3 and REALITY + v3 PSK) must pass timeout, `PreAuthBudget`, `ServerStats`, `AuthRateLimiter`, and peer IP.
- Inside `wait_first_channel`:
  - `OPEN` / `MUX_OPEN` / `UDP_MUX_OPEN` after decrypt + unpad still return the matching `FirstChannel` immediately.
  - WebSocket Ping still gets a Pong and does not count as junk (timeout covers ping-only stall).
  - Other WS types stay ignored; Close / EOF still error as today.
  - A binary frame that decrypts and unpads but is not a channel-open opcode counts via `PreAuthBudgetTracker::note_binary_frame` using the WS binary length (same as pre-AUTH). Budget exhaustion returns an error and calls `auth.record_failure`.
  - Decrypt failures stay fail-fast (`open_client_to_server` error ends the wait). They already drop the session; do not switch to continue-until-budget.
- On wait timeout: `stats.inc_handshake_timeout()`, `auth.record_failure(peer_ip)`, log under `bibavpn_server` (debug) and/or `bibavpn_security` (warn) with `peer_ip` / `session_id`, bail with a message such as `handshake timeout waiting for OPEN / MUX_OPEN / UDP_MUX_OPEN`.
- Update clap help for `--handshake-timeout-secs`, the Prometheus HELP line for `bibavpn_handshake_timeouts_total`, and the AGENTS.md phase list so operators see this wait as a handshake phase.
- Optional small helper in `protocol.rs` (e.g. `classify_v3_first_channel`) so OPEN vs mux vs junk is unit-testable without a live socket. Keep `wait_first_channel` in `bibavpn/src/bin/server.rs`.

## Out of scope

- New CLI flag for a dedicated post-AUTH timeout or a separate junk budget.
- Changing `--handshake-timeout-secs` default, `PreAuthBudget` defaults, or `--handshake-max-junk-bytes`.
- REALITY plaintext first-frame wait (`with_setup_timeout("first frame after REALITY", …)` already bounds that path).
- Mux/UDP bridges after a successful channel open, `--mux-connect-timeout-secs`, or outbound TCP dial.
- Wire-format / opcode changes, client changes, invite JSON, apps, Docker.
- Turning decrypt failures into a continue-until-budget loop (pre-AUTH behaviour). Keep abort-on-decrypt-fail.
- `auth.record_failure` on Close/EOF before a channel open (not a stall/abuse timeout).

## Files to change

- `bibavpn/src/bin/server.rs` — `run_session_after_v3_handshake`, `wait_first_channel`, clap help for `--handshake-timeout-secs`; thread timeout/budget/stats/auth/peer into the wait. Add tokio tests next to the existing `#[cfg(test)]` module (duplex + `WebSocketStream::from_raw_socket`).
- `bibavpn/src/protocol.rs` — optional `classify_v3_first_channel` (or equivalent) wrapping `decode_v3_open_with_flags` / `is_v3_mux_open` / `is_v3_udp_mux_open`; unit tests beside existing protocol tests.
- `bibavpn/src/server_metrics.rs` — HELP text for `bibavpn_handshake_timeouts_total` includes post-AUTH first-channel wait.
- `AGENTS.md` — `--handshake-timeout-secs` phase list and the “Other server timeouts” paragraph mention OPEN / MUX_OPEN / UDP_MUX_OPEN after AUTH.

No `PROTOCOL.md` change (no wire change). Do not touch `biba/`.

## Tests

Run:

```bash
cargo test -p bibavpn
```

Add (names can vary; behaviour must match):

- `protocol.rs`: `classify_v3_first_channel` (or the existing three parsers used together) accepts `encode_v3_open_with_flags`, `encode_v3_mux_open`, `encode_v3_udp_mux_open`; a sealed-control lookalike that is none of those is not a channel open (e.g. `encode_v3_open_ok` or AUTH inner).
- `server.rs` tokio: silent or ping-only peer → `wait_first_channel` errors within a short timeout (use `Duration::from_millis(50)` in the test, not the 15s default); `handshake_timeouts_total` increments.
- `server.rs` tokio: after a sealed padded `MUX_OPEN` (and optionally `OPEN` / `UDP_MUX_OPEN`), `wait_first_channel` returns the matching `FirstChannel` well under the timeout.
- `server.rs` tokio or `server_limits.rs`: more than `max_junk_frames` / `max_junk_bytes` of successfully decrypted non-open binaries fails the wait before the timeout; does not increment `handshake_timeouts_total`.

Use `tokio::io::duplex` + `WebSocketStream::from_raw_socket` in the bin tests. Do not add a new e2e harness, `scripts/*` smoke, or live `bibavpn-server` process.

Optional: `cargo clippy -p bibavpn -- -D warnings` before the PR.

## Acceptance criteria

- A client that completes v3 AUTH and then only sends WebSocket pings or valid AEAD non-open frames is dropped within `--handshake-timeout-secs` (or sooner if junk budget is exceeded). The session error path releases the concurrency permit and `SessionGuard`.
- Timeout path increments `bibavpn_handshake_timeouts_total` and calls `auth.record_failure` for that peer.
- A client that sends `MUX_OPEN` (default path), `OPEN`, or `UDP_MUX_OPEN` inside the window still reaches the existing mux / TCP / UDP bridges with no opcode or framing change.
- Decrypt of a bad ciphertext still fails the wait immediately (existing behaviour).
- `cargo test -p bibavpn` passes, including the new timeout and MUX_OPEN cases.

## Non-goals

- A separate post-AUTH timeout flag or a second junk-budget CLI.
- Punishing slow-but-valid opens that arrive inside the handshake window.
- Changing REALITY AUTH, v3 HELLO/AUTH, or camouflage/TLS setup timeouts.
- Client, JNI, Tauri, or invite-URI work.
- Throughput / DPI / stealth changes.
