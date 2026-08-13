# Spec

## Summary

iOS `connect_inner` builds tunnel start JSON without loading the split-tunnel preset cache, so `split_bypass_domains` is omitted on a cold start even when the user has presets selected. Call `bypass_domains::ensure_loaded(false)` on the iOS connect path before `start_config_json()`, matching Android. `ensure_loaded(false)` already prefers memory → disk → compile-time embed before a network fetch; do not add a separate iOS fetch policy.

## In scope

- In `#[cfg(target_os = "ios")] fn connect_inner`, call `bypass_domains::ensure_loaded(false)` after `persist_cfg` and **before** `g.cfg.start_config_json()`, with the same comment as the Android path (`apps/bibavpn-desktop/src-tauri/src/lib.rs` around the Android block at ~1206–1210).
- Prefer extracting a tiny shared helper (e.g. `fn start_json_with_bypass_cache(cfg: &SavedConfig) -> Result<String, String>`) used by **both** Android and iOS `connect_inner`, so the two mobile paths cannot drift again. Helper body: `let _ = bypass_domains::ensure_loaded(false); cfg.start_config_json()`.
- Ignore `ensure_loaded` errors with `let _ =` (same as Android): connect must still proceed; an empty cache just omits `split_bypass_domains`.
- Add unit coverage in the existing `bibavpn-desktop` crate:
  - Positive: with split tunnel enabled and selected preset ids, after the in-memory cache is seeded, `TunnelProfile::start_config_json()` emits a non-empty `split_bypass_domains`.
  - Regression: the iOS connect path (or the shared helper it calls) loads the cache before building JSON. Because `connect_inner` is `cfg(ios)` and CI runs on Windows/Linux, a source-level assertion on `lib.rs` (e.g. `include_str!`) is acceptable: the iOS function must call `ensure_loaded` / the shared helper **before** `start_config_json`.
- Add a `#[cfg(test)]` cache-seed helper in `bypass_domains.rs` if needed for the positive JSON test (process-global `OnceLock` cache; do not hit the network in tests).

## Out of scope

- Desktop `connect_inner` cache-only race (prefetch vs connect timing). Same class of bug, different fix; keep this PR to the missing iOS call.
- Changing `ensure_loaded` fetch order, timeouts, URL handling, or embed/`build.rs` pipeline.
- A dedicated “iOS must not fetch remote” path. `ensure_loaded(false)` already uses disk/embed first; do not special-case iOS.
- Packet forwarding / tun2socks / issue #73.
- Android `connect_inner` behavior (must stay `ensure_loaded(false)` then `start_config_json()`).
- `bibavpn` / `bibavpn-ffi` / Swift Packet Tunnel / `inject_mobile_tunnel_session_json` (it only injects SOCKS auth; leave `split_bypass_domains` untouched).
- PROTOCOL.md, wire format, CLI, server.

## Files to change

- `apps/bibavpn-desktop/src-tauri/src/lib.rs` — iOS `connect_inner` (required); optional shared helper used by Android + iOS; source-level regression test in the existing `#[cfg(test)]` module.
- `apps/bibavpn-desktop/src-tauri/src/config.rs` — extend `split_bypass_json_tests` with the positive “cache seeded → key present” case. Comment at ~647 is already correct; do not rewrite it.
- `apps/bibavpn-desktop/src-tauri/src/bypass_domains.rs` — `#[cfg(test)]` seed helper only if the JSON test needs it.

## Tests

Run from repo root (matches `.github/workflows/test.yml` desktop job). This is a Tauri app change, not the tunnel crate:

```bash
cargo test -p bibavpn-desktop --locked
```

Focused filters after adding tests:

```bash
cargo test -p bibavpn-desktop --locked split_bypass
cargo test -p bibavpn-desktop --locked ios_connect
```

Do **not** require `cargo test -p bibavpn` / `-p biba` (no tunnel/server/client/biba edits). Do not add an iOS simulator or Packet Tunnel harness.

Existing tests that must keep passing: `split_bypass_json_tests::omitted_when_split_tunnel_disabled` and `omitted_when_no_presets_selected` in `config.rs`.

## Acceptance criteria

- After a cold iOS connect with split-tunnel enabled and preset ids selected, the session JSON passed to `ios_vpn::request_connect` contains a non-empty `split_bypass_domains` whenever those presets exist in memory, disk cache, or the compile-time embed.
- iOS connect still succeeds if `ensure_loaded` fails or the cache/embed is empty (key omitted, same as today).
- Android `connect_inner` still calls `ensure_loaded(false)` before `start_config_json()` and is otherwise unchanged.
- `inject_mobile_tunnel_session_json` does not drop `split_bypass_domains`.
- `cargo test -p bibavpn-desktop --locked` passes.

## Non-goals

- Fixing desktop connect timing vs `prefetch_bypass_domains`.
- Wiring tun2socks / actually applying bypass on the iOS packet path.
- New control-plane API, embed format, or CI secret changes.
- UI changes for split-tunnel presets.
- Cross-compiling or running the iOS `connect_inner` cfg in Linux CI.
