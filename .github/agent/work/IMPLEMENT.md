# Implementation

## Change

`android_split_packages_for_profile` in `apps/bibavpn-desktop/src-tauri/src/split_tunnel.rs` now unions preset-cache packages, `android_manual_split_packages`, and `android_split_tunnel_packages` with the same trim / empty-skip / dedupe rules. `split_tunnel_enabled` remains the gate.

## Tests

`cargo test -p bibavpn-desktop --locked` — **21 passed** (includes 4 new `android_split_packages_tests`).

Note: initial run required `libgtk-3-dev` / `libwebkit2gtk-4.1-dev` and `npm run build` in `apps/bibavpn-desktop/ui` so Tauri’s `frontendDist` exists.
