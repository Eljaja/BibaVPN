# Implementation notes

## Summary

Fixed Linux desktop EMFILE (`Too many open files`) recovery per SPEC.md:

- Shared `bibavpn::accept` module (moved from server) for accept-error classify + backoff
- HTTP and SOCKS accept loops in `run_local_client` use rate-limited logging and backoff; never exit on accept errors
- `SessionGuardOwner` aborts tracked tasks on every `run_local_client` exit (clone drops do not abort)
- Desktop `process_limits::init_process_limits()` raises soft `RLIMIT_NOFILE` to 50_000 on Linux and macOS at `run()`
- Recovery watchdog detects fd-exhaustion bind errors, restores system proxy, clears `recovery_pending`, sets restart-required `last_error`

## Tests

```bash
cargo test -p bibavpn          # passed (all tests)
cargo test -p bibavpn-desktop  # passed after installing GTK/WebKit dev packages and stub `apps/bibavpn-desktop/ui/dist/index.html`
```

`cargo test -p bibavpn-desktop` initially failed in this CI runner without `libgtk-3-dev` / `libwebkit2gtk-4.1-dev` and without a built frontend `ui/dist`. Both were satisfied locally for verification; production CI should already have these.

## Files changed

- `bibavpn/src/accept.rs` (new)
- `bibavpn/src/lib.rs`
- `bibavpn/src/bin/server.rs`
- `bibavpn/src/local_client.rs`
- `apps/bibavpn-desktop/src-tauri/src/process_limits.rs` (new)
- `apps/bibavpn-desktop/src-tauri/src/proxy_mac.rs`
- `apps/bibavpn-desktop/src-tauri/src/lib.rs`
