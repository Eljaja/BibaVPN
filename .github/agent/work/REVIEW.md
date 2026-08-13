VERDICT: PASS

- `validate_control_plane_base_url` is a pure, tested helper: HTTPS-only, no userinfo/query/fragment/extra path, host compared via `Url::host_str()` in canonical `https://host` / `https://host:port` form, empty allowlist rejected. Named accept/reject cases are present; `redeem_import` returns `Err` on `http://` before `ureq`.
- Allowlist is the union of `bypass_domains_url()` origin (https, no hardcoded production host) and saved profile `control_plane_base_url` origins; the POST and persist use the canonical origin, not the raw query value.
- Deeplink redeem writes only in-memory pending state, shows the window, and emits `control-plane-import-pending`. Confirm persists + emits `control-plane-import` / `vpn-state`; cancel drops pending and does not write config. UI modal (ru+en) names CP host and VPN host; `get_pending_import` is read on mount.
- Diff stays in the listed desktop files (`bibavpn` / `biba` untouched). No secrets added. `parse_import_deeplink` still only extracts `token` + `base_url`.
