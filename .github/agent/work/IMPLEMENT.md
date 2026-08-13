# Implementation notes

**Cargo profile note:** The spec’s `[profile.release.package.bibavpn-jni]` / `bibavpn-ffi` `panic = "abort"` blocks cannot be applied — Cargo 1.97 rejects `panic` in `[profile.*.package.*]` (`panic may not be specified in a package profile`). The prior `[profile.mobile-release]` workaround was removed per review. **`catch_unwind` on every `extern` entry is the ABI guard**; existing `android.yml` / `ios.yml` `--release` builds are unchanged.

## Verification

```text
cargo test -p bibavpn-jni -p bibavpn-ffi --locked   # 9 tests (5 jni + 4 ffi), all passed
cargo build -p bibavpn-jni -p bibavpn-ffi --locked  # ok
cargo build -p bibavpn-jni -p bibavpn-ffi --release --locked  # ok
cargo clippy -p bibavpn-jni -p bibavpn-ffi --no-deps --locked -- -D warnings  # ok
```

## Changes

| File | Summary |
|------|---------|
| `apps/bibavpn-jni/src/lib.rs` | `catch_unwind` on all JNI exports; `sanitize_jni_utf8` / `map_jni_string_alloc` helpers for `jni_err` / `jni_json_err` (no `.expect`); mutex `into_inner()`; table-driven unit tests |
| `apps/bibavpn-ffi/src/lib.rs` | `catch_unwind` on all FFI exports; panic-free `leak_cstring`; `-99` panic sentinel on `bibavpn_ffi_start`; mutex `into_inner()`; unit tests |
| `apps/bibavpn-ffi/include/bibavpn_ffi.h` | Document return code `-99` |
| `Cargo.toml` | Removed invalid `[profile.mobile-release]`; spec package `panic` tables omitted (Cargo limitation above) |
| `.github/workflows/test.yml` | Path filter + `mobile` job running JNI/FFI tests on Linux |
