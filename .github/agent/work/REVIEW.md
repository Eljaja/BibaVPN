VERDICT: PASS

- All `extern "system"` / `extern "C"` entries in `bibavpn-jni` and `bibavpn-ffi` are wrapped in `catch_unwind`; panic sentinels match the spec (`jstring` / JSON error, `-99` + heap string, swallow on stop/free).
- JNI `new_string` goes through `sanitize_jni_utf8` + `map_jni_string_alloc` (no `.expect("jstring")`); FFI `leak_cstring` has no `unwrap`. Table-driven tests cover interior-NUL and the alloc-failure mapping.
- `STATE` / `VPN_PROTECT_CLASS` recover poison with `into_inner()`; the sticky `"state mutex poisoned"` errors are gone. Named unit tests cover catch_unwind sentinels, mutex poison, `leak_cstring`, and the JNI helpers.
- Scope matches the spec: header documents `-99`; `test.yml` gained a Linux `cargo test -p bibavpn-jni -p bibavpn-ffi --locked` job; no Kotlin/Swift, `bibavpn` crate, extra workflow, or secret files.
- Workspace `[profile.release.package.*.panic = "abort"]` is omitted because Cargo rejects `panic` in package profile overrides. That belt-and-suspenders line is unsatisfiable as written; `catch_unwind` remains the ABI guard, and existing `--release` mobile CI jobs are unchanged.
