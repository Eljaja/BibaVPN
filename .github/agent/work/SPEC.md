# Spec

## Summary

Android connect builds the per-app bypass list with `split_tunnel::android_split_packages_for_profile`, which unions preset-cache packages and `TunnelProfile.android_manual_split_packages` only. The UI-facing merged list `android_split_tunnel_packages` is never read, so legacy saves, imports, and “connect without opening Settings” never reach JNI `addDisallowedApplication`.

Fix the single connect-path helper: also union `android_split_tunnel_packages` with the same trim / empty-skip / de-dupe rules already used for the manual list. Keep `split_tunnel_enabled` as the gate. Do not migrate fields on load and do not change the UI write path.

## In scope

- Update `android_split_packages_for_profile` so the returned list is the sorted unique union of:
  1. `bypass_domains::cached_android_packages_for_preset_ids(&profile.split_tunnel_preset_ids)`
  2. `profile.android_manual_split_packages`
  3. `profile.android_split_tunnel_packages`
- Apply the existing per-package rules to (3) as well as (2): `trim()`, skip empty, skip if already present (exact string match after trim, same as today’s manual loop).
- Keep current behavior when `split_tunnel_enabled` is false: return an empty `Vec` even if either package field is populated.
- Leave `connect_inner` in `lib.rs` calling this helper; it already passes the result into `android_vpn::request_connect`.
- Add unit tests next to the helper covering a profile that only has `android_split_tunnel_packages` set.

## Out of scope

- Load-time migration of `android_split_tunnel_packages` into `android_manual_split_packages` (the issue’s alternative).
- Stopping the UI from writing `android_split_tunnel_packages` (`androidSplitPackages.js` / Settings remount).
- Domain split on TUN (issue #50), app-picker deadlock (issue #79).
- JNI / Kotlin `VpnService` / `addDisallowedApplication` implementation.
- Wire protocol, `bibavpn` / `biba` crates, iOS, desktop OS proxy bypass.
- Seeding or mocking the bypass-domain preset cache in these tests.

## Files to change

- `apps/bibavpn-desktop/src-tauri/src/split_tunnel.rs` — union `android_split_tunnel_packages` in `android_split_packages_for_profile`; add `#[cfg(test)]` coverage in this file.
- Do not change `apps/bibavpn-desktop/src-tauri/src/config.rs` (`TunnelProfile` already has both fields; sanitization on load already trims/dedupes each vector separately).
- Do not change `apps/bibavpn-desktop/ui/src/androidSplitPackages.js` or `lib.rs` / `android_vpn.rs` unless the helper signature must stay as `fn android_split_packages_for_profile(profile: &TunnelProfile) -> Vec<String>`.

## Tests

Add tests in `apps/bibavpn-desktop/src-tauri/src/split_tunnel.rs` using `TunnelProfile { ..TunnelProfile::default() }` (same pattern as `config.rs` `split_bypass_json_tests`). Do not depend on a populated preset cache: use empty or unknown `split_tunnel_preset_ids`.

Required cases:

1. **Legacy-only packages:** `split_tunnel_enabled = true`, `android_split_tunnel_packages = ["com.legacy.app"]`, `android_manual_split_packages` empty, `split_tunnel_preset_ids` empty. Result contains `"com.legacy.app"`.
2. **Manual + merged, no duplicates:** both fields set, with overlap and one unique each (e.g. merged `["com.a", "com.b"]`, manual `["com.b", "com.c"]`). Result is the sorted unique set (`["com.a", "com.b", "com.c"]`).
3. **Split disabled:** `split_tunnel_enabled = false` with packages in `android_split_tunnel_packages` (and optionally manual). Result is empty.
4. **Trim / empty:** whitespace and empty strings in `android_split_tunnel_packages` are dropped the same way as the manual loop (`"  com.foo  "` becomes `"com.foo"`).

Commands (from repo root; this is the desktop crate, not the tunnel crate):

```bash
cargo test -p bibavpn-desktop --locked
```

Targeted while iterating:

```bash
cargo test -p bibavpn-desktop --locked android_split_packages
```

Do not add JS test harnesses, Android instrumentation, or `cargo test -p bibavpn` for this change.

## Acceptance criteria

- A profile with `split_tunnel_enabled` and packages only in `android_split_tunnel_packages` yields those package names from `android_split_packages_for_profile`. Android connect already forwards that list to JNI, so those apps are excluded via `addDisallowedApplication` without opening Settings.
- Preset-cache packages plus `android_manual_split_packages` plus `android_split_tunnel_packages` still merge; duplicates after trim do not appear twice; output remains sorted.
- With split tunnel disabled, the helper still returns no packages.
- `cargo test -p bibavpn-desktop --locked` passes.

## Non-goals

- Unifying the two profile fields into one persisted field.
- Changing how Settings infers manual vs preset packages.
- Guaranteeing preset-cache hits in unit tests (empty cache is the intended lab case for the legacy-only bug).
- Changing `split_tunnel_enabled` semantics or domain lists (`android_split_domains_for_profile`).
