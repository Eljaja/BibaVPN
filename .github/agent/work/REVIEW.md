VERDICT: PASS

- `decode_udp_rep` rejects remaining payload `> MAX_UDP_PAYLOAD` after `decode_atyp_host_port`, with the check on the slice before `to_vec()`, and bails with `"udp rep payload too large"`.
- Unit test `udp_rep_decode_payload_max_enforced` covers an exact `MAX_UDP_PAYLOAD` reply (xid/host/port/length) and an empty-then-appended `MAX_UDP_PAYLOAD + 1` record that must `Err`; existing `udp_req_rep_roundtrip` and `udp_rep_includes_trailing_in_payload` are unchanged.
- Diff is limited to `bibavpn/src/protocol.rs`; REQ/encode paths, `MAX_UDP_PAYLOAD`, and wire layout are untouched. No secrets. `cargo test -p bibavpn` in TEST.log: 0 failed, including the new `udp_tests` case.
