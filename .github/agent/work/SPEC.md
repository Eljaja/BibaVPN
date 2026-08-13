# Spec

## Summary

Android `nativeStop` currently `take()`s `STATE` to `None`, waits 5s, then **detaches** a still-running client thread and clears `outbound_protect`. A following `nativeStart` thinks the process is idle and spawns a second tokio client, which can double-bind SOCKS (`127.0.0.1:1080`) and overwrite the protect hook while the old WSS session is still alive.

Fix the JNI slot so a timed-out stop stays visible as “stopping” (fail closed / wait-then-start, never two live clients). Clear the protect hook only after the old thread has actually exited. In `BibaVpnService.performFullStackRestart`, treat JNI `"already running"` the same way `enqueueBootstrapWorker` already does: log and keep the tunnel, do not Toast-fail and `setTunnelActive(false)`.

Keep the 5s stop bound (ANR). Do not join forever.

## In scope

- **JNI client slot** in `apps/bibavpn-jni/src/lib.rs`:
  - After `stop_client_bounded` times out, **do not** leave `STATE == None`. Keep the `JoinHandle` / `done_rx` in a stopping slot so the process is not idle.
  - `nativeStart` must either wait (bounded by the existing 5s stop join timeout) for that stopping thread and only then spawn, or return `"already running"`. It must never start a second client while the previous thread is still alive.
  - `nativeStop` on an already-stopping slot may wait again (same 5s bound) and then join if the thread finished; it must not spawn anything.
  - The SOCKS-not-ready failure path in `nativeStart` (today: `guard.take()` + `stop_client_bounded` + `set_hook(None)`) must use the same stop helper so a timeout there also leaves a stopping slot and does not clear the hook early.
- **Protect hook:** on Android, call `bibavpn::outbound_protect::set_hook(None)` only after the client thread has joined (`done_rx` disconnected / `JoinHandle::join`). On stop timeout, leave the existing hook installed.
- **Kotlin restart:** in `performFullStackRestart`, if `nativeStart` returns a string containing `"already running"` (same `ERR_ALREADY_RUNNING` as bootstrap), log a warning and **continue to `startVpnTunnel`**. Do not Toast, do not `setTunnelActive(false)`, do not `return@Thread` before TUN/tun2socks.
- Extract the stop/start slot logic far enough that `cargo test -p bibavpn-jni` can cover it without a device (parameterize the join timeout so tests can use tens of milliseconds, not 5s). Holding `STATE` for that bounded wait is acceptable: Java already serializes start/stop with `nativeLifecycleLock`, and `nativeStart` already runs off the main thread.

Suggested slot behavior (implement this, not a larger state machine):

1. **Idle** (`None`): `nativeStart` spawns; `nativeStop` is a no-op.
2. **Live:** `nativeStart` → `"already running"` if `!thread.is_finished()`; `nativeStop` signals shutdown and waits up to 5s.
3. **Stopping** (shutdown already sent, thread may still run): `nativeStart` waits up to 5s for `done_rx` disconnect, joins, then spawns; if still running → `"already running"`. Never bind SOCKS twice.

## Out of scope

- iOS `bibavpn-ffi` unbounded join (issue #73) and any FFI `STATE` changes.
- Server target fd leak (issue #67).
- Background reaper thread / generation counter beyond what is required to keep a stopping slot and avoid a second spawn.
- Aborting or `std::thread::kill` of the client thread; changing `STOP_JOIN_TIMEOUT` (5s) for production.
- Desktop `ActiveVpn::stop`, tun2socks `Engine`, TUN recreate, bootstrap worker, or `onDestroy` teardown flow (except the restart `"already running"` branch above).
- Wire format, `bibavpn` crate, `biba` crate, `outbound_protect.rs` API shape (JNI already calls `set_hook`; only **when** JNI calls `None` changes).
- New Android/JUnit/device harnesses.

## Files to change

- `apps/bibavpn-jni/src/lib.rs` — `NativeState` / `STATE`, `stop_client_bounded`, `Java_dev_bibavpn_core_BibaNative_nativeStart`, `Java_dev_bibavpn_core_BibaNative_nativeStop`; optional small private module in the same crate if that makes the slot testable without JNI.
- `apps/bibavpn-jni/Cargo.toml` — only if needed so unit tests compile (e.g. `crate-type = ["cdylib", "rlib"]`). Prefer the smallest Cargo change that lets `cargo test -p bibavpn-jni` run.
- `apps/bibavpn-desktop/src-tauri/android-bibavpn-extras/java/dev/bibavpn/BibaVpnService.kt` — `performFullStackRestart` error handling for `ERR_ALREADY_RUNNING` only.

## Tests

Run from repo root:

```bash
cargo test -p bibavpn-jni
cargo clippy -p bibavpn-jni -- -D warnings
```

Do **not** require `cargo test -p bibavpn` / `-p biba` (those crates are untouched). Do not add Gradle/device tests.

Add unit tests next to the extracted slot logic (dummy `std::thread` that ignores shutdown and sleeps, or that exits when a test `watch` fires):

- Stop timeout leaves a stopping slot (`STATE` not idle); a following start either waits until the dummy thread exits then starts once, or returns `"already running"` — never two live dummy threads.
- Stop that joins (thread exits inside the timeout) clears the slot and a following start succeeds.
- A test double for the protect hook is **not** cleared on timeout and **is** cleared after a successful join.
- `nativeStart`-equivalent “already running” while a live (non-stopping) thread is still running remains an error.

Use a test-only join timeout (~50–200ms), not the production 5s.

## Acceptance criteria

- `nativeStop` followed immediately by `nativeStart` never runs two client threads against the same SOCKS bind. If the old thread is still alive after the bounded wait, start fails closed with `"already running"`.
- A stop that hits the 5s timeout does not clear `outbound_protect` until that old thread has joined.
- Network-change / full-stack restart (`performFullStackRestart`): `"already running"` from JNI does not Toast, does not `setTunnelActive(false)`, and does not skip `startVpnTunnel`.
- `nativeStop` still returns within the existing 5s bound (no unbounded `join` on the teardown path).
- `cargo test -p bibavpn-jni` and `cargo clippy -p bibavpn-jni -- -D warnings` pass.

## Non-goals

- Fixing every Android lifecycle race (screen-off battery saver, duplicate `onStartCommand`, tun2socks join).
- Making stop instantaneous or aborting in-flight `getaddrinfo` / tokio runtime drop.
- Changing the public JNI signatures of `nativeStart` / `nativeStop`.
- Documenting or renaming the `"already running"` error string (Kotlin already matches it).
- Camouflage, REALITY, proto-3, or any on-wire change.
