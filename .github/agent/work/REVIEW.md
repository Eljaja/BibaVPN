VERDICT: PASS

- Client UDP mux stores DNS expect `(id, qname)` only for parseable queries to port 53, removes pending `xid` before any snoop, and skips `record_dns` for unknown `xid`, non-DNS originals (`dns_expect` is `None`), and replies whose `sp != 53`.
- `record_dns` / `record_dns_response` require matching DNS id + normalized qname, `matches_bypass`, keep the existing TTL clamp / `MAX_ENTRIES`, and refuse a live different-name overwrite; same name may refresh, expired IPs may rebind.
- Named `domain_route` tests (forged qname, id mismatch, legitimate match, non-bypass, no live overwrite, query parser truncated/loop) and `split_bypass_wiring.rs` (matched `0x1234` / `example.com`) are present; `cargo test -p bibavpn` in TEST.log is 0 failed. Diff is only the three spec files; no wire-format, extra crates, or secrets.
