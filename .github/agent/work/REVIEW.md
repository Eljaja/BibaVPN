VERDICT: PASS

- Linux/macOS desktop `run()` raises soft `RLIMIT_NOFILE` via `process_limits` (50_000, hard-capped, never lowers `cur`); Android/iOS are excluded.
- Server accept classify/backoff/tests moved to public `bibavpn::accept`; HTTP and SOCKS loops in `run_local_client` classify, rate-limit on `bibavpn_client`, sleep on backoff, and never `?` on accept errors.
- `SessionGuardOwner` aborts tracked tasks on every `run_local_client` exit; `SessionGuard` clones do not. Required owner-drop / clone-drop / EMFILE-transient cases are present.
- Watchdog treats bind/accept EMFILE-class strings as terminal: restores system proxy (`disconnect_inner(..., true)`), sets a distinct restart `last_error`, clears `recovery_pending`. Other reconnect errors keep 2s→30s fail-closed backoff.
- Named cases for `desired_nofile_soft` and `is_fd_exhaustion_message` are present. Diff stays inside the listed files; no secrets, wire/mux, or out-of-scope policy changes.
