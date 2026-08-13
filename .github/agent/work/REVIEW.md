VERDICT: PASS

- `pickInstalledLauncherPackage` on the main looper returns `ERROR:main_thread` immediately; it no longer spawns a worker or `await`s a latch on main.
- Off-main path still posts the picker via `runOnUiThread` and waits on the caller-thread latch; `released`/`finish` still blocks a late `onResult` from double-`countDown`.
- Off-main wait is 60s and still returns `ERROR:timeout`; JNI prefixes remain `PACKAGE:…` / `CANCEL` / `ERROR:…`.
- Diff is limited to `pickInstalledLauncherPackage` and `pickInstalledLauncherPackageWorker` in `TauriVpnBridge.kt`; no extra files, secrets, or out-of-scope edits.
- Named tests: `cargo test -p bibavpn` passed (optional sanity). Gradle compile skipped because `gen/android` is absent, which the spec allows. No new test harness added.
