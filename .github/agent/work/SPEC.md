SIZE: SMALL
# Spec
## Summary
Rust `extern` entry points in `bibavpn-jni` (Android) and `bibavpn-ffi` (iOS) can panic and unwind into the JVM / Swift runtime, which is undefined behavior. The JNI path uses `.expect("jstring")` on every `JNIEnv::new_string`, and `VPN_PROTECT_CLASS.lock().unwrap()` can panic from `nativeStart`. The FFI crate has the same class of risk on every `extern "C"` (plus a leftover `.unwrap()` in `leak_cstring`). Desktop already recovers poisoned mutexes with `into_inner()`; JNI/FFI should match that and also catch panics at the ABI boundary.

Do not change the public JNI/C signatures or the success/error contract already used by Kotlin and Swift.

## In scope
- Wrap every `extern "system"` / `extern "C"` body in `std::panic::catch_unwind` (`AssertUnwindSafe` as needed) so a panic never crosses the ABI.
- Sentinel values on catch (must match today’s callers; **do not** treat panic as success):
  - `nativeStart` / `nativeStop`: error `jstring` (Kotlin `String?`; `null` means success). If `new_string` also fails, `throw_new("java/lang/RuntimeException", …)` and return `null` so the existing `catch (Throwable)` paths in `BibaVpnService` still see a failure.
  - `nativeDecodeInvite`: JSON `{"ok":false,"error":"…"}` `jstring`, never `null` (Kotlin declares non-null `String`). Same `throw_new` last resort.
  - `bibavpn_ffi_start`: unused error code **-99**, `*err_out` set to a heap string (free with `bibavpn_ffi_string_free`).
  - `bibavpn_ffi_decode_invite`: leaked JSON error string (header already says the pointer is non-null on the happy path; keep that for panic too).
  - `bibavpn_ffi_stop` / `bibavpn_ffi_string_free`: swallow and return.
- Replace all JNI `.expect("jstring")` (including `jni_err`) with a helper that returns a `jstring` or throws as above. No `expect` / `unwrap` on the FFI/JNI hot path.
- Poisoned `Mutex`es (`STATE`, `VPN_PROTECT_CLASS`): `unwrap_or_else(|p| p.into_inner())`, same as `apps/bibavpn-desktop/src-tauri/src/lib.rs`. Drop the “state mutex poisoned” hard-error returns that currently treat poison as fatal.
- Make `leak_cstring` panic-free (the fallback literal has no interior NUL; use a path that cannot `unwrap`).
- Release-profile abort as belt-and-suspenders (workspace root only; crate-level `[profile]` is ignored):

```toml
[profile.release.package.bibavpn-jni]
panic = "abort"

[profile.release.package.bibavpn-ffi]
panic = "abort"
```

  Dev/test keep `unwind`, so `catch_unwind` unit tests work. Shipped Android/iOS release builds abort instead of unwinding if a new `extern` is added without a wrapper.

- Document `-99` on `bibavpn_ffi_start` in `apps/bibavpn-ffi/include/bibavpn_ffi.h`.
- Host unit tests next to the helpers (see Tests). No new device/emulator harness.

## Out of scope
- Desktop Tauri panic hook (`set_hook` that only logs). Tauri commands are not a C/JNI `extern` boundary; aborting the whole desktop process is a product change.
- Changing Kotlin / Swift call sites, JNI method names, or C ABI layouts beyond documenting `-99`.
- `panic = "abort"` for `bibavpn`, `biba`, or `bibavpn-desktop`.
- Rewriting start/stop threading, SOCKS ready timeout, or `outbound_protect`.
- Full Xcode IPA / Gradle APK / emulator smoke in this PR (existing `android.yml` / `ios.yml` builds stay the mobile compile check).
- Wire-format, proto-3, or `bibavpn` crate changes.

## Files to change
- `apps/bibavpn-jni/src/lib.rs` — catch_unwind on `nativeStart` / `nativeStop` / `nativeDecodeInvite`; `jni_err` / `new_string` helper; mutex `into_inner`; `#[cfg(test)]` for helpers + a function that panics inside `catch_unwind`.
- `apps/bibavpn-ffi/src/lib.rs` — same for `bibavpn_ffi_start` / `_stop` / `_decode_invite` / `_string_free`; panic-free `leak_cstring`; tests for `-99` and JSON panic sentinel.
- `apps/bibavpn-ffi/include/bibavpn_ffi.h` — note that `-99` means an internal panic was caught.
- `Cargo.toml` (workspace) — `[profile.release.package.bibavpn-jni]` and `[profile.release.package.bibavpn-ffi]` `panic = "abort"`.
- `.github/workflows/test.yml` — path-filter + `cargo test -p bibavpn-jni -p bibavpn-ffi --locked` on Linux when those crates (or the workspace `Cargo.toml`) change, so the new tests actually run. Do not add a new workflow file.

## Tests
From repo root (host Linux; no NDK/JVM/Xcode required):

```bash
cargo test -p bibavpn-jni -p bibavpn-ffi --locked
cargo build -p bibavpn-jni -p bibavpn-ffi --locked
```

Recommended before PR:

```bash
cargo clippy -p bibavpn-jni -p bibavpn-ffi -- -D warnings
```

Unit tests must cover at least:
- `catch_unwind` around a helper that `panic!`s returns the JNI/FFI sentinel (error JSON / `-99`), not a resume-unwind.
- Poisoned `Mutex`: `into_inner()` lets a subsequent lock proceed (mirror the desktop poison test in `bibavpn-desktop`).
- `leak_cstring` / JNI string helper: interior-NUL or `new_string` failure path does not panic (table-driven on the Rust helper; do not stand up a JVM).

Do not add `cargo test -p bibavpn` unless this PR accidentally touches `bibavpn`. Existing CI `android.yml` (`cargo build -p bibavpn-jni --release`) and `ios.yml` (`cargo build -p bibavpn-ffi --target aarch64-apple-ios`) are the Android/iOS compile smoke; do not invent an emulator or device job.

## Acceptance criteria
- No `extern "system"` / `extern "C"` in `bibavpn-jni` or `bibavpn-ffi` can unwind into the caller: every entry is wrapped in `catch_unwind`, and release builds of those two packages use `panic = "abort"`.
- No `.expect("jstring")` / `.unwrap()` on JNI `new_string` or FFI `CString` construction on those paths.
- JNI/FFI mutex poison uses `into_inner()`, not a panic or a sticky “poisoned” error that permanently blocks start/stop.
- Panic on `nativeStart` is reported as an error string (or a Java exception), never as `null` success. Panic on `nativeDecodeInvite` / `bibavpn_ffi_decode_invite` is a JSON error object, not a null pointer.
- `cargo test -p bibavpn-jni -p bibavpn-ffi --locked` passes. `cargo build -p bibavpn-jni -p bibavpn-ffi --locked` passes. Existing Android JNI and iOS FFI CI builds stay green.

## Non-goals
- Recovering from panics *inside* the client worker thread after it has already crossed into `run_local_client` (that thread is not an `extern` boundary; log-and-exit there is fine).
- Making `catch_unwind` recover in `panic = "abort"` release builds (abort is the intended last line).
- Changing invite JSON shape, token/PSK handling, or any on-wire protocol.
- Hardening the desktop app’s global panic hook or aborting Tauri on panic.
