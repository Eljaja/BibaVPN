# Implementation

Closed the DNS injection path for full-TUN split-bypass routing.

## Changes

### `bibavpn/src/domain_route.rs`
- Added `parse_dns_query` (header id + first question name).
- Extended `parse_dns_answers` to return the DNS message id.
- `record_dns_response` now requires matching `(expected_id, expected_qname)`, filters by bypass list, and refuses to overwrite a live IP mapping with a different normalized name.
- `record_dns` global hook takes `expected_id` and `expected_qname`.
- Unit tests: forged qname, id mismatch, legitimate match, non-bypass qname, no live overwrite, query parser (including truncation/compression loop).

### `bibavpn/src/udp_mux.rs`
- Pending UDP mux entries store optional DNS expect `(id, qname)` when forwarding a parseable query to port 53.
- On `UDP_REP`, pending `xid` is removed first; `record_dns` runs only when pending matched, `sp == 53`, and DNS expect is present.

### `bibavpn/tests/split_bypass_wiring.rs`
- Updated `record_dns` calls to pass matched id `0x1234` and qname.

## Tests

```bash
cargo test -p bibavpn
```

All tests passed in this environment.
