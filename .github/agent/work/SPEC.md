SIZE: SMALL
# Spec
## Summary

Literal LAN / loopback / RFC1918 / CGNAT / IPv6 ULA / link-local targets are sent through the tunnel. The VPS cannot reach them, so `curl -x http://127.0.0.1:17890 http://192.168.x.x/` hangs while a direct request succeeds.

Root cause is two missing always-direct paths: `domain_route::decide` / `should_bypass` only treat an IP as `Direct` after a DNS-snoop map hit (and both short-circuit to Tunnel when the split-tunnel list is empty), and desktop OS proxy ignore lists only force loopback. Fix both in one PR: always classify private/local hosts as `Route::Direct` in the core matcher, and add the matching RFC1918 / ULA / link-local / `*.local` entries to Linux, macOS, and Windows system-proxy bypass lists.

## In scope

1. **Core matcher.** Add `host_is_local_or_private(host: &str) -> bool` in `bibavpn/src/domain_route.rs`. Call it at the **top** of both `decide` and `should_bypass` (before the empty-bypass early returns). Those early returns stay for public hosts: empty split-tunnel list still means `Tunnel` for `example.com` and `1.1.1.1`.

   Treat as local/private:
   - IPv4: loopback `127.0.0.0/8`, RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local `169.254.0.0/16`, CGNAT `100.64.0.0/10`.
   - IPv6: loopback `::1`, ULA `fc00::/7`, link-local `fe80::/10`, and IPv4-mapped `::ffff:x.x.x.x` after mapping to the inner v4.
   - Hostname `localhost` (ASCII case-insensitive; trim a single trailing `.`).

   CGNAT: match octets (`first == 100 && second >= 64 && second <= 127`). Do **not** use unstable `Ipv4Addr::is_shared`.

2. **Existing unit tests that used `10.0.0.1` as a stand-in public IP** in `domain_route.rs` (`decide_ip_via_map`, `record_accepts_legitimate_match`, and any expiry/unknown-IP assertion on that address) must switch the mapped address to TEST-NET `203.0.113.0/24`. After this change `10.0.0.1` is always `Direct`, so those cases would otherwise become tautologies. Do not rewrite unrelated `10.0.0.1` fixtures in `protocol.rs` / `http_connect.rs` / `incoming.rs`.

3. **HTTP CONNECT regression** in `local_client.rs` (next to `http_connect_split_bypass_reaches_origin_directly`): `set_bypass_domains(&[])`, `CONNECT 127.0.0.1:<origin-port>` to a local origin, 3s timeout. Must reach the origin (200 + ping/pong) and must not wait on mux. Reset the global list in a `finally`-style cleanup as the existing test does.

4. **Desktop OS bypass lists** (always merged, not only when split-tunnel domains are set):
   - Linux `merge_ignore_hosts` and `no_proxy_list`: add `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `100.64.0.0/10`, `fc00::/7`, `fe80::/10`, `*.local` (Linux ignore-hosts already has loopback).
   - macOS `merge_bypass_for_apply`: the same CIDRs (it already has `*.local`).
   - Windows `merge_proxy_override`: `<local>`, `10.*`, `192.168.*`, `169.254.*`, `100.*`, and `172.16.*` … `172.31.*` (WinInet has no CIDR). Keep existing `<-loopback>` and Steam/WebView entries.

## Out of scope

- Hostname `.local` / mDNS matching in the **core** matcher (OS `*.local` lists are enough).
- Sending any LAN/private range through the VPS under any profile or flag.
- Mux epoch / stream-id wrap, EMFILE accept-loop recovery, camouflage, proto 3 / REALITY / PSK, wire format.
- New CLI flags, UI toggles, invite fields, or a user-facing “bypass LAN” setting.
- Android TUN `excludeRoute` / iOS Packet Tunnel routing tables (desktop HTTP/SOCKS + OS proxy lists only).
- UDP mux datagrams to LAN resolvers (SOCKS/HTTP CONNECT TCP is the reported bug).

## Files to change

- `bibavpn/src/domain_route.rs` — `host_is_local_or_private`; call it first in `decide` and `should_bypass`; retarget `10.0.0.1` DNS-map tests to `203.0.113.x`; add private/empty-list unit cases.
- `bibavpn/src/local_client.rs` — HTTP CONNECT empty-list + `127.0.0.1` regression (HTTP CONNECT already uses `should_bypass` / `resolve_domain_split_route`; no production path change beyond the matcher).
- `apps/bibavpn-desktop/src-tauri/src/proxy_linux.rs` — required CIDRs / `*.local` in `merge_ignore_hosts` and `no_proxy_list`; extend existing merge / `NO_PROXY` unit tests.
- `apps/bibavpn-desktop/src-tauri/src/proxy_mac.rs` — same CIDRs in `merge_bypass_for_apply`; add a small merge unit test (none exists today).
- `apps/bibavpn-desktop/src-tauri/src/proxy_win.rs` — WinInet wildcards in `merge_proxy_override`; add a small merge unit test.

## Tests

Concrete commands (no new harness):

```bash
cargo test -p bibavpn
cargo test -p bibavpn-desktop
```

Required cases:

- `decide("192.168.88.1", &[], …) == Direct`; same for `10.0.0.1`, `172.16.1.1`, `127.0.0.1`, `localhost`, `::1`, `fc00::1`, `::ffff:192.168.1.1`. Also `100.64.1.1` (CGNAT) and `169.254.1.1` / `fe80::1`.
- `decide("1.1.1.1", &[], …) == Tunnel`; `decide("example.com", &[], …) == Tunnel`.
- DNS-map tests that previously used `10.0.0.1` as a mapped public IP now use `203.0.113.x`: known+live → Direct, unknown / expired → Tunnel.
- `should_bypass("192.168.88.1")` is true after `set_bypass_domains(&[])` (or equivalent: empty global list must not hide the always-direct check). Reset globals after the test.
- HTTP CONNECT: empty bypass list + `CONNECT 127.0.0.1` reaches the origin within 3s (does not block on mux).
- `bibavpn/tests/split_bypass_wiring.rs` still passes (`example.com` / public `93.184.216.34` behavior unchanged).
- Linux: merged `ignore-hosts` and `NO_PROXY` contain `192.168.0.0/16` and `10.0.0.0/8` (extend `merge_adds_loopback_and_split` / `proxy_env_assignments`).
- macOS merge includes `192.168.0.0/16` and `10.0.0.0/8`; Windows merge includes `<local>`, `10.*`, `192.168.*`, and `172.16.*`.

## Acceptance criteria

- Private / loopback / CGNAT / ULA / link-local literals and `localhost` are `Route::Direct` even when the split-tunnel domain list is empty.
- Public IPs and ordinary hostnames with an empty bypass list remain `Tunnel`.
- HTTP CONNECT to `127.0.0.1` with `set_bypass_domains(&[])` reaches the origin; it does not wait on mux.
- Linux merged `ignore-hosts` / `NO_PROXY` contain `192.168.0.0/16` and `10.0.0.0/8`. macOS and Windows merge helpers include the lists in **In scope**.
- `cargo test -p bibavpn` and `cargo test -p bibavpn-desktop` pass. No protocol / mux / wire-format changes.

## Non-goals

- Do not send LAN through the VPS under any profile.
- Do not change mux/epoch or the EMFILE accept loop.
- Do not match `.local` hostnames in `host_is_local_or_private` (OS `*.local` only).
- Do not add a user-facing toggle to force private ranges into the tunnel.
- Do not invent a new test harness or live `curl` / GNOME e2e job.
