SIZE: SMALL
# Spec
## Summary

Linux desktop dies overnight on `Too many open files` (EMFILE): the HTTP accept loop busy-spins and floods the log, SOCKS `accept` `?`-exits `run_local_client` without aborting the HTTP task, leftover fds block rebind, and the recovery watchdog keeps the system proxy pointed at a dead local port.

Fix it in one client/desktop PR: raise `RLIMIT_NOFILE` on Linux the same way macOS already does, share the server’s accept-error backoff with both local listeners, abort session tasks on every `run_local_client` exit, and stop EMFILE recovery from retrying bind while leaving the OS proxy applied.

## In scope

1. **Raise soft `NOFILE` on Linux desktop** to the same target as macOS (`50_000`, capped by the hard limit, never lowering the current soft limit). Call it at process start in `bibavpn_desktop::run()`. Do not call it on Android/iOS.

2. **Share accept recovery.** Move `AcceptRecovery`, `ACCEPT_BACKOFF` (100 ms), `is_accept_resource_exhaustion`, and `classify_accept_error` out of `bibavpn/src/bin/server.rs` into a small public `bibavpn` module. Use that helper on **both** HTTP and SOCKS accept loops in `run_local_client`. On any accept error: classify, rate-limit the log (`LogEvery`, target `bibavpn_client`), sleep when `backoff()` is `Some`, continue. Never `?` out of `run_local_client` for a per-connection accept error (including EMFILE/ENFILE).

3. **Abort session tasks on every exit from `run_local_client`.** `SessionGuard` is `Clone` (shared `Arc` of `JoinHandle`s); do **not** `impl Drop` on the cloneable guard (a per-connection drop would abort the whole session). Hold a **non-cloned owner** only inside `run_local_client` that calls a synchronous abort of tracked tasks on drop (and/or wrap the body so every `?` / return runs abort). The existing clean `shutdown.changed()` path may still call `abort_all`; abort must be idempotent. After a SOCKS/mux/`?` failure the HTTP accept task must die so the listen port can bind again in the same process.

4. **Watchdog failsafe for fd exhaustion.** If `connect_inner` / `run_local_client` fails with a bind/accept EMFILE-class error (`Too many open files`, `os error 24`, raw 24/23 on Unix), do **not** keep `recovery_pending` and retry bind. Surface a distinct `last_error` (user must restart the app), clear `recovery_pending`, and restore the system proxy (`disconnect_inner(..., true)` / `restore_proxy_blocking`) so the machine is not black-holed until kill. Sleep/network recovery policy is unchanged for all other errors.

## Out of scope

- Mux epoch / stream-id wrap (#103), server mux `CLOSE-WAIT` leak (#67), wire format, proto 3, REALITY, PSK.
- `parse_ignore_hosts_list` comma-in-comment bug in `proxy_linux.rs`.
- Telegram SOCKS4 vs SOCKS5-only (`unsupported socks version 4`).
- IPv6 AAAA with no default route.
- Raising `NOFILE` on Android, iOS, or `bibavpn-server` / CLI `bibavpn-client`.
- Changing default fail-closed recovery for sleep/network-change (non-EMFILE) cases.
- New product UI, new CLI flags, new transports.

## Files to change

- `bibavpn/src/accept.rs` (new) — move `AcceptRecovery`, `ACCEPT_BACKOFF`, `classify_accept_error`, `is_accept_resource_exhaustion`, and the existing server unit tests from `bin/server.rs`. Export from `bibavpn/src/lib.rs`.
- `bibavpn/src/bin/server.rs` — delete the local copies; import the shared helper. Accept-loop behavior stays the same.
- `bibavpn/src/local_client.rs` — HTTP loop (`http_listener.accept`, today logs and spins) and SOCKS loop (`res.context("socks accept")?`) both use classify + backoff + continue; `SessionGuard` owner abort on all exits; extend `session_shutdown_tests`.
- `apps/bibavpn-desktop/src-tauri/src/process_limits.rs` (new, `cfg(unix)` desktop only) — portable `getrlimit`/`setrlimit` extracted from `proxy_mac::init_process_limits` (WANT = 50_000). Keep a tiny pure helper (e.g. `desired_nofile_soft(cur, hard, want)`) for unit tests.
- `apps/bibavpn-desktop/src-tauri/src/proxy_mac.rs` — remove `init_process_limits` (or re-export the shared fn so macOS behavior is unchanged).
- `apps/bibavpn-desktop/src-tauri/src/lib.rs` — call process limits for Linux **and** macOS desktop in `run()` (replace `#[cfg(target_os = "macos")]` only). In `spawn_tunnel_recovery_watch`, classify fd-exhaustion errors and stop retry + restore proxy. Add a small `is_fd_exhaustion_message` helper + tests next to existing `lib.rs` unit tests.

## Tests

Concrete commands (no new harness):

```bash
cargo test -p bibavpn
cargo test -p bibavpn-desktop
```

Required cases (add or move; do not invent a live `prlimit` e2e job):

- Existing server cases, now in `bibavpn` `accept` module: transient `ErrorKind`s → `RetryNow`; `OutOfMemory` / raw EMFILE(24), ENFILE(23), ENOMEM, ENOBUFS → exhaustion + `Some(ACCEPT_BACKOFF)`; unknown kind → backoff without exhaustion flag; `ACCEPT_BACKOFF` in 50–250 ms.
- `local_client`: `io::Error::from_raw_os_error(24)` is classified as exhaustion+backoff and is **not** a fatal `run_local_client` accept error (helper or loop policy function; do not require a mocked `TcpListener` unless cheap).
- `session_shutdown_tests`: tracked task is aborted when the **owner** is dropped / error-path cleanup runs, **without** going through `shutdown.changed()`. Dropping a **clone** of `SessionGuard` must not abort tasks.
- Desktop: `desired_nofile_soft` (or equivalent) never lowers `cur`; result is `min(want, hard)` when `hard` is finite and `want > cur`.
- Desktop: `is_fd_exhaustion_message` is true for `bind socks 127.0.0.1:17891: Too many open files (os error 24)` and false for a normal TLS/timeout string.

## Acceptance criteria

- After Linux desktop `run()`, soft `RLIMIT_NOFILE` is `min(50_000, hard)` and `≫ 1024` when the hard limit allows it (same as current macOS).
- HTTP and SOCKS accept on EMFILE/ENFILE: rate-limited log, ~100 ms sleep, loop continues; `run_local_client` does not return `Err` for that accept.
- Any `run_local_client` error or return aborts the HTTP accept task; the listen port can bind again in the same process.
- Recovery watchdog: EMFILE on bind/reconnect restores the system proxy, sets a distinct `last_error`, and does not keep `recovery_pending` retries. Other reconnect failures still fail-closed with 2s→30s backoff.
- `cargo test -p bibavpn` and `cargo test -p bibavpn-desktop` pass. No protocol / mux-epoch / wire-format changes.

## Non-goals

- Full fd-leak audit of mux writers, decoy GETs, or Chromium/Electron client sockets.
- Automatically raising the **hard** `NOFILE` (requires privileges; GUI scopes already have a large hard limit).
- Changing camouflage, server listen semaphore, or `bibavpn-server` accept policy beyond the extract/import.
- Documenting a user-facing “restart required” dialog beyond `last_error` / existing vpn-state emit.
