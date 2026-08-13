VERDICT: PASS

- JNI slot matches the spec machine: timed-out stop keeps `JoinHandle`/`done_rx` in Stopping (not idle), does not clear the protect-hook callback, and does not detach.
- `nativeStart` on Stopping waits the bounded join timeout then spawns or returns `"already running"`; a live non-stopping thread still errors; SOCKS-not-ready uses the same stop helper (`abort_pending_start` → `stop`).
- `performFullStackRestart` treats `ERR_ALREADY_RUNNING` like bootstrap (log only, no Toast, no `setTunnelActive(false)`, no early `return@Thread`) and continues to `startVpnTunnel`.
- Named slot tests are present with a ~100ms join timeout (timeout leaves Stopping + hook uncleared; successful join clears slot/hook and start succeeds; live thread rejects start; never two live dummies). Diff stays in the allowed files; no secrets.
