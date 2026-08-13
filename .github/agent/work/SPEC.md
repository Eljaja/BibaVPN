# Spec

## Summary

The full-TUN split-bypass path learns `IP → domain` from DNS inside `UDP_REP`. Today any reply with source port 53 is ingested (`udp_mux.rs` calls `domain_route::record_dns` **before** the pending mux `xid` check, and with no check that the payload answers a query this client sent). A malicious or compromised VPS can emit `sp=53` plus a DNS blob whose `qname` is on the bypass list, pointing at an attacker IP; the next tun2socks `CONNECT` to that IP then goes **Direct**.

This PR closes that injection path. Ingest a DNS answer only when it matches a pending UDP mux datagram this client sent to port 53, the DNS transaction id and question name match that query, and the `qname` is on the configured bypass list. Keep the existing TTL clamp. Do not replace a still-live mapping for an IP with a different `qname`.

This is client-side policy only. The UDP mux wire format (`UDP_REQ` / `UDP_REP`) does not change.

## In scope

1. **Gate snooping on a real pending DNS query** in the client UDP mux session (`run_udp_mux_one_session`):
   - When forwarding `ClientUdpCmd::Forward` with `dst_port == 53`, parse the DNS query payload for `(id: u16, qname)` and store it next to the pending mux `xid` (same map that already holds the oneshot reply).
   - If `dst_port != 53`, or the payload is not a parseable DNS question, store no DNS expect (do not snoop the matching reply).
   - On `UDP_REP`, **remove / look up pending `xid` first**. Unknown `xid` (unsolicited reply): do **not** call `record_dns`.
   - Call the snoop only when all of: pending `xid` matched, original `dst_port` was 53 (stored expect is `Some`), reply `sp == 53`, and the payload matches the stored DNS `id` + `qname`.

2. **Harden `DomainRouteMap` ingest** in `domain_route.rs`:
   - Add a query parser (header id + first question name, same name rules as `parse_dns_answers`: lowercase, compression-safe, jump cap).
   - Extend answer parsing so a response’s 16-bit DNS id is available for the match (keep today’s A/AAAA extraction).
   - Record A/AAAA only if: DNS id equals the expected id, `qname` equals the expected question (trim trailing `.`, ASCII case-insensitive), and `matches_bypass(qname, bypass_list)` is true.
   - On insert: keep `MIN_TTL_SECS` (30) / `MAX_TTL_SECS` (3600) clamp and `MAX_ENTRIES`. If the IP already has a **live** entry whose domain is a **different** normalized name, skip that IP (do not overwrite). Same name may refresh TTL. After expiry, a different name may take the IP.
   - Process-global `record_dns` used by the mux must take the expected `(id, qname)` (or a thin wrapper that does). Keep the no-op when the global bypass list is empty.

3. **Tests** covering forged `qname`, unmatched id, unsolicited ingest, legitimate bypass DNS, and no live overwrite (see Tests).

## Out of scope

- DNSSEC, DoH/DoT, or authenticating resolver answers beyond “this is the reply to a query we sent”.
- Lying A/AAAA for a name the client **did** query through the tunnel (the VPS already sees that query). Fail-closed Direct is only required when the client did **not** ask for that name.
- Unsigned remote bypass-list fetch (issue #66) and Android `excludeRoute` (issue #50).
- Server UDP mux, `PROTOCOL.md` / wire layout, JNI/Tauri UI, or changing `decide` / `should_bypass` matching rules except as a consequence of not recording poisoned IPs.
- Raising or removing the existing TTL clamp or `MAX_ENTRIES`.

## Files to change

- `bibavpn/src/udp_mux.rs` — pending map stores optional DNS expect; snoop only after pending `xid` match and `sp == 53` with that expect. Do not snoop unsolicited `UDP_REP`.
- `bibavpn/src/domain_route.rs` — query parse; matched ingest; bypass-list filter; refuse live different-`qname` overwrite; unit tests in the existing `#[cfg(test)]` module.
- `bibavpn/tests/split_bypass_wiring.rs` — update the `record_dns` call to the new matched API (the helper already uses DNS id `0x1234`); keep the “learned bypass IP goes Direct / non-bypass IP stays Tunnel” assertions.

Do not add new crates, test binaries, or scripts.

## Tests

Run:

```bash
cargo test -p bibavpn
```

Add or extend unit tests in `bibavpn/src/domain_route.rs` (`#[cfg(test)]`):

- **Forged bypass `qname`:** `record_*` with expected query `other.org` / id `A`, payload a valid A response for `example.com` (on the bypass list) → 0 IPs recorded; `decide("attacker-ip", bypass, map, now)` stays `Route::Tunnel`.
- **Id mismatch:** same question name, different DNS id → not recorded.
- **Legitimate match:** expected id + `qname` on the bypass list → IP recorded; `decide` on that IP is `Route::Direct`.
- **Non-bypass `qname`:** matched id/qname but name not on the list → not recorded (map stays empty for that IP).
- **No live overwrite:** IP mapped to `example.com` still live; a matched response for a different bypass name with the same A → mapping stays `example.com`. After expiry, the other name may bind.
- **Query parser:** extracts id + qname from a question; truncated / looped compression still `None`.

Keep existing parse / TTL / `decide` tests passing.

`bibavpn/tests/split_bypass_wiring.rs` must still pass (start JSON installs bypass list; a **matched** snoop of `example.com` makes that IP Direct; `other.org` does not).

No new harness. Mux session I/O need not be integration-tested if the pending-gate is a small, obvious call-site change and matching logic is covered in `domain_route`.

## Acceptance criteria

- A `UDP_REP` with `sp=53` and a DNS blob whose `qname` is on the bypass list does **not** make a later `CONNECT` to that answer IP go Direct unless this client sent a UDP mux request with that pending `xid` to port 53 whose DNS id and question name match the reply.
- Unsolicited `UDP_REP` (unknown mux `xid`) with `sp=53` is not ingested.
- A reply to a non-DNS UDP request (`dst_port != 53`) is not ingested even if `sp=53`.
- A real DNS reply for a configured bypass domain (matching pending query) still maps those A/AAAA IPs so `should_bypass` / `decide` returns Direct for those IPs until TTL expiry.
- A live `IP → domain` entry is not replaced by a different `qname` before expiry.
- `cargo test -p bibavpn` passes. No wire-format change.

## Non-goals

- Making split-tunnel Direct safe against a VPS that answers the user’s **own** DNS questions with attacker A/AAAA.
- Changing how bypass domains are fetched, stored, or suffix-matched.
- Server, protocol, or app-layer work beyond the two modules and the wiring test above.
