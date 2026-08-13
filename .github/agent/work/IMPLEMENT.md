# Implementation

On Linux CI, `cargo test -p bibavpn-desktop` requires `apps/bibavpn-desktop/ui` built (`npm install && npm run build`) and GTK/WebKit dev packages (`libglib2.0-dev`, etc.). Tests passed here after those steps.

## Changes

- Added `start_json_with_bypass_cache` shared helper (Android + iOS): calls `bypass_domains::ensure_loaded(false)` then `SavedConfig::start_config_json()`.
- iOS `connect_inner` now uses the helper before `inject_mobile_tunnel_session_json`, matching Android.
- `bypass_domains::seed_test_cache` for unit tests (no network).
- Positive JSON test: seeded cache → non-empty `split_bypass_domains`.
- Source regression test: iOS `connect_inner` must use the shared helper (CRLF-safe `include_str!` check).

## Tests

```text
cargo test -p bibavpn-desktop --locked  → 19 passed
cargo test -p bibavpn-desktop --locked split_bypass  → 3 passed
cargo test -p bibavpn-desktop --locked ios_connect  → 1 passed
```
