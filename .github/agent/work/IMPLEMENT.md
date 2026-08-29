# Implementation notes

**Clippy:** `cargo clippy -p bibavpn-jni -- -D warnings` fails in this environment because transitive workspace crates (`biba`, `bibavpn`) emit pre-existing warnings promoted to errors under `-D warnings`. The `bibavpn-jni` crate itself is clean: `cargo clippy -p bibavpn-jni --no-deps -- -D warnings` passes.

## Summary

Fixed Android JNI client lifecycle so a timed-out `nativeStop` leaves a **stopping** slot (not idle), preventing a second SOCKS client from spawning. `outbound_protect::set_hook(None)` runs only after a successful thread join. `performFullStackRestart` treats JNI `"already running"` like bootstrap: log and continue to `startVpnTunnel`.

## Files changed

- `apps/bibavpn-jni/src/client_slot.rs` — new Idle/Live/Stopping slot manager + unit tests
- `apps/bibavpn-jni/src/lib.rs` — wire slot manager into `nativeStart` / `nativeStop`
- `apps/bibavpn-jni/Cargo.toml` — add `rlib` crate-type for unit tests
- `apps/bibavpn-desktop/src-tauri/android-bibavpn-extras/java/dev/bibavpn/BibaVpnService.kt` — `ERR_ALREADY_RUNNING` handling in `performFullStackRestart`

## Tests run

```bash
cargo test -p bibavpn-jni          # 8 passed
cargo clippy -p bibavpn-jni --no-deps -- -D warnings  # passed
```
