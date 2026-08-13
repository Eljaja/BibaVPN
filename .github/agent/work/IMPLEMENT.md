# Implementation

Desktop control-plane import hardening per SPEC.md.

## Changes

- **`control_plane_client.rs`**: `validate_control_plane_base_url`, `origin_from_service_url`, `build_allowed_origins`; `redeem_import` validates before HTTP and returns canonical origin.
- **`lib.rs`**: Deeplink flow stores pending import in memory; `get_pending_import`, `confirm_pending_import_cmd`, `cancel_pending_import_cmd`; emits `control-plane-import-pending`.
- **`config.rs`**: `profile_control_plane_origins` helper for allowlist union.
- **`App.jsx` / `i18n.js`**: Dark in-app confirm modal (ru+en).
- **`Cargo.toml`**: direct `url` dependency; `Cargo.lock` updated.

## Tests

```bash
cargo test -p bibavpn-desktop --locked
```

All 34 unit tests pass (Linux runner with GTK/WebKit dev packages and UI `npm run build`).
