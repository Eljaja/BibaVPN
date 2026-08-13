VERDICT: PASS

- Post-AUTH `wait_first_channel` is wrapped in a fresh `tokio::time::timeout(params.handshake_timeout)` (not leftover AUTH time). Both `run_session_after_v3_handshake` callers (plain v3 and REALITY + v3 PSK) pass timeout, `PreAuthBudget`, stats, auth limiter, and peer IP.
- Timeout increments `handshake_timeouts_total`, calls `auth.record_failure(peer_ip)`, logs `peer_ip` / `session_id` under `bibavpn_server` (debug) and `bibavpn_security` (warn), and returns the specified error so the existing `SessionGuard` / semaphore path can release.
- Channel opens still classify via `classify_v3_first_channel` after decrypt+unpad; Ping still Pongs and is not junk; Close/EOF still error without `record_failure`; decrypt stays fail-fast; non-open AEAD binaries use `PreAuthBudgetTracker::note_binary_frame` on WS binary length and `record_failure` on budget exhaustion.
- Docs/CLI/metrics updates are in-scope only (`--handshake-timeout-secs` clap help, Prometheus HELP, AGENTS.md phase lists). No wire/client/`biba/`/`PROTOCOL.md` changes, no new timeout/junk CLI, no secrets.
- Named tests are present and passed in `cargo test -p bibavpn`: `classify_v3_first_channel_opcodes`; silent and ping-only waits at 50ms with timeout counter; sealed `MUX_OPEN` / `OPEN` / `UDP_MUX_OPEN`; junk budget fail without incrementing `handshake_timeouts_total`.
