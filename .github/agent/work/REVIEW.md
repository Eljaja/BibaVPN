VERDICT: PASS

- SOCKS and HTTP CONNECT send the success reply before IP:443 SNI peek; hostname / DNS-map Direct still replies then relays with no peek.
- Peek uses incremental `read` into one buffer and forwards leftover bytes as `client_prefetch` on the tunnel path; Direct writes the peeked prefix then `copy_bidirectional`.
- `extract_client_hello_sni` is a pure parser in `domain_route.rs` (not REALITY / fingerprint code). Named unit tests are present and passed; `cargo test -p bibavpn` passed, including existing `domain_route` tests and `split_bypass_wiring`.
- `startVpnTunnel` no longer calls `applySplitTunnelDomainBypasses()` (no domain `excludeRoute`). Per-app `addDisallowedApplication` is unchanged. `android_split_note` ru/en no longer claims Android 13+ / resolve-at-connect. `split_tunnel.rs` is comment-only.
- Diff stays in the spec file list; no `PROTOCOL.md` change; no secrets.
