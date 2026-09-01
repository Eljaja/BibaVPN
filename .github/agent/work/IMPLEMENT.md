# Implementation notes

## Summary

Private / loopback / CGNAT / ULA / link-local literals and `localhost` are always routed `Direct`, even when the split-tunnel domain list is empty. Desktop OS proxy bypass lists now include matching RFC1918 / ULA / link-local / `*.local` entries on Linux, macOS, and Windows.

## Tests

```bash
cargo test -p bibavpn          # passed (all tests, incl. split_bypass_wiring + new domain_route/local_client cases)
cargo test -p bibavpn-desktop  # passed after installing libgtk-3-dev / libwebkit2gtk-4.1-dev and stub ui/dist/index.html
```

macOS (`proxy_mac::tests`) and Windows (`proxy_win::tests`) merge unit tests compile but run only on their respective targets (`#[cfg(target_os = ...)]` modules).

## Files changed

- `bibavpn/src/domain_route.rs` — `host_is_local_or_private`; early Direct in `decide` / `should_bypass`; DNS-map tests retargeted to `203.0.113.x`; new private/empty-list unit cases
- `bibavpn/src/local_client.rs` — HTTP CONNECT empty bypass list + `127.0.0.1` regression test
- `apps/bibavpn-desktop/src-tauri/src/proxy_linux.rs` — private CIDRs in `merge_ignore_hosts` / `no_proxy_list`; extended unit tests
- `apps/bibavpn-desktop/src-tauri/src/proxy_mac.rs` — private CIDRs in `merge_bypass_for_apply`; merge unit test
- `apps/bibavpn-desktop/src-tauri/src/proxy_win.rs` — WinInet wildcards in `merge_proxy_override`; merge unit test
