VERDICT: PASS

- iOS `connect_inner` calls `start_json_with_bypass_cache` after `persist_cfg` and before `inject_mobile_tunnel_session_json` / `ios_vpn::request_connect`.
- Shared helper (Android + iOS) is `let _ = bypass_domains::ensure_loaded(false); cfg.start_config_json()`, so Android still loads the cache then builds JSON and is otherwise unchanged.
- `inject_mobile_tunnel_session_json` is untouched (SOCKS auth only; `split_bypass_domains` is not dropped).
- Named tests are present: `present_when_cache_seeded_and_presets_selected`, source-level `ios_connect_loads_bypass_cache_before_start_json`, and the two existing omission tests are unchanged.
- `seed_test_cache` is test-only and does not hit the network; no secrets; no out-of-scope product files (desktop connect, `ensure_loaded` fetch policy, FFI/Swift, PROTOCOL/CLI/server).
