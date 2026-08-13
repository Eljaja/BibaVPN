# Spec

## Summary

Fix the Android split-tunnel app picker deadlock in `TauriVpnBridge.pickInstalledLauncherPackage`. Today, if the JNI caller is already on the main looper, the method starts a worker and **blocks main** on a 120s latch while that worker posts back with `activity.runOnUiThread` and waits on a second latch. Main never runs the posted work, so “add app to bypass” hangs until timeout.

A synchronous wait for `startActivityForResult` cannot complete on the main looper: the result is delivered on that same looper. Mirror `requestConnect` in the same file: run/post UI work to main, and **wait only from a non-main thread**. If already on main, return `ERROR:…` immediately instead of waiting.

## In scope

- `pickInstalledLauncherPackage` thread routing:
  - **Not on main** (normal Wry JNI path; file comment already states JNI is not `Looper.getMainLooper()`): keep posting the picker launch with `runOnUiThread` and wait on the existing result latch from that caller thread.
  - **On main**: do **not** spawn a worker that posts back to main, and do **not** `CountDownLatch.await` on main (short timeouts still freeze/ANR). Return `ERROR:main_thread` immediately. JNI reply strings stay `PACKAGE:…` / `CANCEL` / `ERROR:…` so `parse_pick_reply` in `android_vpn.rs` stays valid.
- Cap the **off-main** wait at **60 seconds** (same as `requestConnect`), returning `ERROR:timeout` instead of 120s.
- Keep the `released`/`finish` guard so a late `onResult` after timeout cannot double-countDown.
- Short comment next to the main-thread branch explaining why a blocking pick cannot run on main (same idea as the existing `requestConnect` / Wry-looper comment).

## Out of scope

- Making a real package pick complete when the caller **is** the main looper (would need async JNI / a Rust-side channel; not this PR).
- `PickInstalledPackageActivity` UI, listing, or extras.
- `android_vpn.rs` / `parse_pick_reply` / the Rust `recv_timeout(125)` unless a later change makes the Kotlin wait exceed 125s (it will not).
- iOS, standalone `apps/android/`, protocol, server, or `bibavpn` crate.

## Files to change

- `apps/bibavpn-desktop/src-tauri/android-bibavpn-extras/java/dev/bibavpn/TauriVpnBridge.kt` — `pickInstalledLauncherPackage` and `pickInstalledLauncherPackageWorker` only.

## Tests

This is Android Kotlin extras, not the tunnel crate. Do **not** add Robolectric, Espresso, or any new test harness.

```bash
# Tunnel crate is untouched; optional sanity only:
cargo test -p bibavpn
```

Compile the merged extras when `apps/bibavpn-desktop/src-tauri/gen/android` already exists (after `tauri android init`):

```bash
bash apps/scripts/integrate-bibavpn-into-tauri-android.sh
(cd apps/bibavpn-desktop/src-tauri/gen/android && ./gradlew :app:compileDebugKotlin)
```

If `gen/android` is missing, skip Gradle; do not invent a standalone Kotlin test project.

Manual on a device/emulator: Settings → “add app to bypass” (`pick_installed_package_cmd`). Picker must open without a ~120s freeze; Cancel → no package added; pick → `PACKAGE:…` applied.

## Acceptance criteria

- Calling `pickInstalledLauncherPackage` **on the main looper** returns `PACKAGE:…`, `CANCEL`, or `ERROR:…` without blocking main on a latch the UI work must release (immediate `ERROR:main_thread` is acceptable).
- Calling it from a **background JNI thread** still launches `PickInstalledPackageActivity` and returns `PACKAGE:…`, `CANCEL`, or `ERROR:…`.
- Off-main wait is ≤ 60s; expiry returns `ERROR:timeout` rather than hanging the UI.
- Reply prefixes consumed by `parse_pick_reply` are unchanged.

## Non-goals

- Async/callback picker API, Tauri plugin rewrite, or changing the JNI signature `(Landroid/app/Activity;)Ljava/lang/String;`.
- Altering split-tunnel preset/domain logic or the desktop/UI settings screen.
- PROTOCOL.md / wire-format work.
