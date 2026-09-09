SIZE: SMALL
# Spec
## Summary

`BibaVpnService` intends to skip a full-stack restart on a short display bounce: `SCREEN_ON` within 500 ms of `SCREEN_OFF`. That guard is dead. The receiver calls `maybeRestartStackAfterUnlockEvent("SCREEN_ON")`, but the bounce check compares `source == Intent.ACTION_SCREEN_ON` (`"android.intent.action.SCREEN_ON"`). The 2.5 s restart throttle still runs.

Unify the event identity so the existing 500 ms rule is reachable, extract the decision so it can be tested without a device, and add enough lifecycle timing logs to tell bounce / unlock / network-change restarts apart. Do not treat this as proof that the user’s sleep/wake delay is the debounce bug; there is no device trace.

## In scope

1. **Single event identity.** Introduce a small typed event (enum or sealed class) used by both the `BroadcastReceiver` and the restart decision. Suggested names: `UnlockRestartEvent.SCREEN_ON` and `UnlockRestartEvent.USER_PRESENT`, with those same short strings in logs. Do not pass the short string `"SCREEN_ON"` and compare it to `Intent.ACTION_SCREEN_ON`. Prefer one source of truth over dual string constants.

2. **Extract the existing decision** into an Android-SDK-free helper, e.g. `UnlockRestartPolicy.decide(...)`, so tests do not need `VpnService` or `SystemClock`. Preserve today’s policy exactly:
   - `allowRestart == false` → skip (current `allowScreenOnStackRestart`).
   - Bounce (`< 500 ms` since `SCREEN_OFF`) applies **only** to `SCREEN_ON`. `USER_PRESENT` must not be filtered by that rule (AOD bounce must not block a real unlock).
   - `now - lastRestart < 2500` → skip (existing throttle).
   - Missing/blank saved config → skip.
   - Otherwise schedule one restart and record `lastRestart` **before** enqueueing work (same as today).
   - Threshold: `499` ms is bounce; `500` ms is not.

3. **Call site.** `maybeRestartStackAfterUnlockEvent` takes the typed event, reads elapsed times, calls `decide`, logs the decision, and on `Restart` calls the existing `requestFullStackRestart`. Keep recovery off the main looper: the receiver only decides and enqueues; `nativeStop` / `nativeStart` / TUN / tun2socks stay on the existing worker.

4. **Queued follow-up after STOP.** In `performFullStackRestart`’s `finally`, do not run a queued restart if the user already requested teardown (`ACTION_STOP` / `enqueueTeardownWorker`). A dedicated `stopRequested` (or equivalent) flag set on explicit stop and cleared only on a user-initiated connect is enough. Do not redesign the queue.

5. **Logs (narrow).** Keep existing `scheduling` / `begin` / `queued` lines. Add elapsed fields already known locally: `since_screen_off_ms`, `since_last_restart_ms`, `decision`, and phase durations inside the restart worker (`nativeStop`, `nativeStart`, TUN/tun2socks). Never log token, PSK, invite, PEM, or the session SOCKS URL/credentials.

6. **Integrate copy list.** New production Kotlin under `java/dev/bibavpn/` must be added to the explicit `cp` loop in `integrate-bibavpn-into-tauri-android.sh`.

7. **Investigation (code + logs only).** Review `SCREEN_ON` → `USER_PRESENT` and network-callback interleaving against the current throttle/queue. Do **not** change network-change recovery or coalescing unless a test or the current control flow shows a redundant second `requestFullStackRestart` that bypasses the 2.5 s throttle. Record in the implementation report what the static bug fix proves and what still needs a device logcat.

## Out of scope

- Session resumption / fast reconnect (#35), new handshakes, stream replay, QUIC, wire-format or proto-3/REALITY changes.
- JNI stop-timeout / zombie-client race (#83). Do not retune the 5 s / 20 s native waits.
- Moving `requestConnect` / bootstrap back onto the main looper (#122).
- Removing full restarts, changing battery-saver defaults, or guaranteeing “instant wake” / surviving TCP streams across sleep.
- Changing `--udp-socket-pool`, mux windowing, or tun2socks Engine timeouts.
- Device farms, new Gradle modules, or a new CI workflow. If `gen/android` or a handset is missing, say so.

## Files to change

- `apps/bibavpn-desktop/src-tauri/android-bibavpn-extras/java/dev/bibavpn/UnlockRestartPolicy.kt` — **create**: typed event + `decide` (no `android.*` imports).
- `apps/bibavpn-desktop/src-tauri/android-bibavpn-extras/java/dev/bibavpn/BibaVpnService.kt` — receiver passes the typed event; helper uses `decide`; STOP clears queued follow-up; narrow timing logs.
- `apps/scripts/integrate-bibavpn-into-tauri-android.sh` — copy `UnlockRestartPolicy.kt` next to `BibaVpnService.kt`.
- `apps/scripts/test_unlock_restart_policy.py` — **create**: host regression (same style as `apps/scripts/test_merge_bibavpn_manifest.py`). Must fail on the audited mismatch (`"SCREEN_ON"` vs `Intent.ACTION_SCREEN_ON`) and execute the bounce / boundary / `USER_PRESENT` / throttle / disabled / no-config table against `UnlockRestartPolicy` (compile+run the extracted Kotlin with `kotlinc` when present; if `kotlinc` is missing, still fail the static discriminator check and print that policy execution was skipped — do not invent a green Kotlin run).

Do not change `apps/bibavpn-jni`, `bibavpn/src/local_client.rs`, or `PROTOCOL.md`.

## Tests

Concrete commands (no new CI workflow):

```bash
python3 apps/scripts/test_unlock_restart_policy.py
python3 apps/scripts/test_merge_bibavpn_manifest.py
```

`test_unlock_restart_policy.py` must cover:

- Static: `BibaVpnService` no longer calls the helper with `"SCREEN_ON"` / `"USER_PRESENT"` while the bounce branch compares `Intent.ACTION_SCREEN_ON`. After the fix, both sides use `UnlockRestartEvent` (or the same `Intent.ACTION_*` value if that alternative is chosen). This check must fail on the audited source.
- Static: `integrate-bibavpn-into-tauri-android.sh` copies `UnlockRestartPolicy.kt`.
- Policy table (when `kotlinc` can compile `UnlockRestartPolicy.kt` + a small `main`/`.kts` driver in `apps/scripts/` or extras `test/`):
  - `SCREEN_ON` at 0 ms and 499 ms since `SCREEN_OFF` → bounce skip.
  - `SCREEN_ON` at 500 ms, last restart ≥ 2500 ms, allow + config → restart.
  - `USER_PRESENT` at 100 ms since `SCREEN_OFF`, last restart ≥ 2500 ms, allow + config → restart (bounce must not apply).
  - `SCREEN_ON` at 5000 ms since off, 2499 ms since last restart → throttle skip.
  - `allowRestart = false` → skip even if timings would restart.
  - `hasSavedConfig = false` → skip.
- STOP queue: a unit-level assertion or source check that the queued-rerun path is gated on “user stop not requested” (the new flag), so `ACTION_STOP` cannot resurrect the tunnel.

If `apps/bibavpn-desktop/src-tauri/gen/android` exists after a local integrate, optionally:

```bash
cd apps/bibavpn-desktop/src-tauri/gen/android && ./gradlew :app:testDebugUnitTest --tests dev.bibavpn.UnlockRestartPolicyTest
```

Do not claim that Gradle or device smoke passed when those trees/devices are absent.

Do **not** run `cargo test -p bibavpn` for this change unless `bibavpn` or `bibavpn-jni` is touched (they should not be).

## Acceptance criteria

- The 500 ms `SCREEN_ON` bounce guard is reachable with the same event value the receiver passes. A host test fails on the audited comparison and passes after the fix.
- Bounce, 500 ms boundary, `USER_PRESENT` inside the bounce window, 2.5 s throttle, restart-disabled, and missing-config cases match the policy above.
- Restart work stays off the main looper; overlapping triggers still serialize through the existing `restartLock` / one-queued-follow-up path (no parallel `nativeStart`).
- A physical-network change can still schedule a restart the way it does today. `ACTION_STOP` does not apply a stale queued restart.
- Connected/error publication still follows the existing TUN/native lifecycle (`setTunnelActive` / `recordConnectError`); do not leave `isTunnelActive == true` after a failed restart.
- Implementation notes separate the fixed static bug from unverified device latency. No “instant wake” claim.

## Non-goals

- Do not add session resumption or change the tunnel handshake.
- Do not retune JNI / tun2socks timeouts or treat `#83` log lines as this bug.
- Do not weaken socket protect, AUTH, or PSK.
- Do not change screen-off battery-saver defaults.
- Do not add a user-facing “skip restart on wake” setting.
- Do not invent a green device trace or a new Android CI job.
