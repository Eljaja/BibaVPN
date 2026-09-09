# Implementation notes

## Fixed static bug

`BroadcastReceiver` passed the short strings `"SCREEN_ON"` / `"USER_PRESENT"` into `maybeRestartStackAfterUnlockEvent`, but the 500 ms bounce guard compared `source == Intent.ACTION_SCREEN_ON` (`"android.intent.action.SCREEN_ON"`). The comparison never matched, so every `SCREEN_ON` skipped the bounce filter and only the 2.5 s throttle applied.

Both paths now use `UnlockRestartEvent` and `UnlockRestartPolicy.decide(...)` (Android-SDK-free, host-testable). Bounce applies only to `SCREEN_ON`; `USER_PRESENT` is never filtered by the 500 ms rule.

## STOP vs queued restart

`stopRequested` is set in the `ACTION_STOP` branch and at the top of `enqueueTeardownWorker` (before the `teardownInProgress` early return), and cleared when the user initiates connect in `onStartCommand`. `performFullStackRestart`’s `finally` skips a queued follow-up when `stopRequested` is true.

## Native lifecycle lock

`stopTunnelAndNative()` and `BibaNative.nativeStart(...)` run in one `synchronized(nativeLifecycleLock)` block inside `performFullStackRestart`; `nativeStop_ms` / `nativeStart_ms` are timed inside that block so `enqueueBootstrapWorker` cannot interleave a second `nativeStart`.

## Lifecycle / network interleaving (code review only)

| Trigger | Throttle | Bounce | Queue |
|--------|----------|--------|-------|
| `SCREEN_ON` | 2.5 s via policy | 500 ms since `SCREEN_OFF` | `restartLock` serializes |
| `USER_PRESENT` | 2.5 s | none | same |
| Physical network change | 2.5 s in `scheduleFullRestartAfterNetworkChange` (+ 1.5 s debounce) | none | same |

Network-change restarts still call `requestFullStackRestart` directly; they do not bypass the 2.5 s throttle (checked before `lastFullStackRestartElapsed` is updated). No change to network recovery was required — no redundant second restart bypassing throttle was found in static review.

## What still needs device logcat

- End-to-end latency from sleep/wake to tunnel active (tun2socks `Engine.start`, WSS handshake) — not proven by this fix.
- Whether `SCREEN_ON` → `USER_PRESENT` ordering on a given OEM always delivers `USER_PRESENT` after AOD bounce when the user unlocks.
- Interleaving of network callbacks with unlock events under real Wi‑Fi ↔ LTE handoff.

Do **not** claim “instant wake” from this change; only the unreachable bounce guard and clearer timing logs.

## Tests

```bash
python3 apps/scripts/test_unlock_restart_policy.py   # passed (kotlinc policy table if available)
python3 apps/scripts/test_merge_bibavpn_manifest.py  # passed
```

Optional Gradle unit test not run (`gen/android` may be absent in CI agent).

## Files changed

- `apps/bibavpn-desktop/src-tauri/android-bibavpn-extras/java/dev/bibavpn/UnlockRestartPolicy.kt` — typed event + `decide`
- `apps/bibavpn-desktop/src-tauri/android-bibavpn-extras/java/dev/bibavpn/BibaVpnService.kt` — policy integration, `stopRequested`, timing logs
- `apps/scripts/integrate-bibavpn-into-tauri-android.sh` — copy `UnlockRestartPolicy.kt`
- `apps/scripts/test_unlock_restart_policy.py` — host regression
- `apps/scripts/unlock_restart_policy_driver.kt` — kotlinc policy table driver
