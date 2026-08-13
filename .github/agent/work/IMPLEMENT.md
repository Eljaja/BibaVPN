# Implementation notes

## Change

`TauriVpnBridge.pickInstalledLauncherPackage`: on the main looper, return `ERROR:main_thread` immediately instead of blocking on a worker that posts back to main. Off-main path unchanged (post picker via `runOnUiThread`, wait on caller thread). Off-main latch timeout reduced from 120s to 60s.

## Tests

| Command | Result |
|---------|--------|
| `cargo test -p bibavpn` | **PASS** (186 tests) |
| `integrate-bibavpn-into-tauri-android.sh` + `./gradlew :app:compileDebugKotlin` | **Skipped** — `apps/bibavpn-desktop/src-tauri/gen/android` not present (no `tauri android init` in this environment) |
| Manual device: Settings → add app to bypass | **Not run** — requires Android device/emulator |
