VERDICT: PASS

- Typed `UnlockRestartEvent` is shared by the receiver and `UnlockRestartPolicy.decide`; bounce uses the same identity (`SCREEN_ON`), so the old `"SCREEN_ON"` vs `Intent.ACTION_SCREEN_ON` mismatch is gone.
- Extracted policy matches the specified table (499 ms bounce, 500 ms restart, `USER_PRESENT` not bounced, 2499 ms throttle, `allowRestart=false`, missing config). `lastRestart` is recorded before enqueue. No `android.*` in the helper.
- `stopRequested` is set on `ACTION_STOP` and at the top of `enqueueTeardownWorker` (before the in-progress return), cleared only on a connect path, and gates the `finally` queued rerun.
- `stopTunnelAndNative` + `nativeStart` stay in one `nativeLifecycleLock`; phase timings are inside that block. Network-change recovery is unchanged. Restart work stays on the existing worker thread.
- Named host tests exist and pass (`test_unlock_restart_policy.py` including kotlinc table, `test_merge_bibavpn_manifest.py`). Integrate script copies `UnlockRestartPolicy.kt`. No secrets, no JNI/core/PROTOCOL, no extra product scope.
