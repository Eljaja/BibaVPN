# Implementation notes

## Summary

Split mobile/desktop `StateSnapshot` assembly into a brief `Inner` copy, lock-free Android/iOS tunnel probe, and epoch-gated re-lock so late JNI callbacks cannot revive stale connected state, profile, or errors. Sync IPC commands that can wait on tunnel JNI now use `spawn_blocking`.

Review follow-up: fixed Android use-after-move in `assemble_state_snapshot` (`probe.as_ref()` instead of `unwrap_or_default()`); added `pin_cert_pem` redaction assertions in `assembled_public_cfg_omits_secrets`.

## Tests

```bash
# Linux CI: install GTK/WebKit dev packages and ensure ui/dist exists (or run npm build first)
sudo apt-get install -y libgtk-3-dev libwebkit2gtk-4.1-dev
npm run build --prefix apps/bibavpn-desktop/ui

cargo test -p bibavpn-desktop   # passed (67 tests, incl. new snapshot_assemble_tests)
npm run build --prefix apps/bibavpn-desktop/ui   # passed
```

## Files changed

- `apps/bibavpn-desktop/src-tauri/src/lib.rs` — `Inner.epoch`; `SnapshotCopy` / `TunnelProbe` / `assemble_state_snapshot` / `snapshot_with_probe`; epoch bumps on disconnect, connect completion/failure, invite/import/save; all former `snapshot()` callers; `spawn_blocking` on `get_state`, `save_config_cmd`, `clear_error_cmd`, `apply_invite_cmd`, `confirm_pending_import_cmd`, `open_control_plane_refresh_cmd`; unit tests in `snapshot_assemble_tests`
