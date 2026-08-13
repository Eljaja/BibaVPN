VERDICT: PASS

- `android_split_packages_for_profile` still gates on `split_tunnel_enabled` and returns a sorted unique union of preset-cache packages, `android_manual_split_packages`, and `android_split_tunnel_packages`, with the same trim / empty-skip / exact-match de-dupe as the existing manual loop.
- Helper signature is unchanged; `connect_inner` in `lib.rs` is untouched and still forwards the helper result to `android_vpn::request_connect`.
- Diff is limited to `apps/bibavpn-desktop/src-tauri/src/split_tunnel.rs`; no load-time field migration, UI write-path changes, JNI/Kotlin, or other out-of-scope files.
- All four named unit tests are present next to the helper (`legacy_only`, manual+merged de-dupe, split disabled → empty, trim/empty skip) using `TunnelProfile { ..TunnelProfile::default() }` and empty preset ids.
- No secrets or extra crates/test harnesses in the product diff.
