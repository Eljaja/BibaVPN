# Spec

## Summary

`decode_udp_rep` in `bibavpn/src/protocol.rs` copies every byte after the SOCKS-like address into a `Vec` with no size check. `decode_udp_req`, `encode_udp_req`, and `encode_udp_rep` already reject payloads larger than `MAX_UDP_PAYLOAD` (`60 * 1024`). Add the same cap to `decode_udp_rep` so an oversized inner `0x06` UDP_REP cannot force a huge allocation or a huge SOCKS UDP datagram. Wire layout is unchanged.

## In scope

- In `decode_udp_rep`, after `decode_atyp_host_port`, reject when the remaining payload length is greater than `MAX_UDP_PAYLOAD` (same constant and comparison as `decode_udp_req`: `payload.len() > MAX_UDP_PAYLOAD`). Prefer checking the slice length **before** `to_vec()` so the oversized record is not allocated; a post-copy check matching `decode_udp_req` is acceptable if it is the smaller edit.
- Bail with an error in the same style as `decode_udp_req` (`"udp req payload too large"`), e.g. `"udp rep payload too large"`.
- Add a unit test in the existing `udp_tests` module that an oversized REP is rejected. `encode_udp_rep` already refuses oversized payloads, so build a valid small REP (or empty payload) and append bytes until the inner payload is `MAX_UDP_PAYLOAD + 1`, then assert `decode_udp_rep` is `Err`.
- Assert an in-range reply still decodes: payload of length `MAX_UDP_PAYLOAD` (and the existing `udp_req_rep_roundtrip` / `udp_rep_includes_trailing_in_payload` cases).

## Out of scope

- Changing `MAX_UDP_PAYLOAD` or the UDP_REQ / UDP_REP byte layout (`0x05` / `0x06`).
- Changing `decode_udp_req`, `encode_udp_req`, or `encode_udp_rep` (already capped).
- `udp_mux.rs`, SOCKS UDP framing (`build_socks5_udp_datagram` / `parse_socks5_udp_datagram`), outer WS / `--udp-max-ws-binary` / `--max-ws-binary` caps, `record_dns`, or client/server CLI.
- Documenting the 60 KiB cap in `PROTOCOL.md` (layout is unchanged; encode/REQ already enforce it).
- New test binaries, smoke scripts, or Docker e2e.

## Files to change

- `bibavpn/src/protocol.rs` — `decode_udp_rep` (~line 271) and `udp_tests` (extend `udp_payload_max_enforced` or add a sibling test next to it).

## Tests

Run from the repo root:

```bash
cargo test -p bibavpn
```

Focused check of the module tests (optional extra, not a substitute):

```bash
cargo test -p bibavpn --lib protocol::udp_tests
```

Do not add a new harness. Keep `udp_rep_includes_trailing_in_payload` passing (one extra trailing byte is still under the cap).

## Acceptance criteria

- `decode_udp_rep` returns `Err` when the payload after ATYP/address/port is larger than `MAX_UDP_PAYLOAD`.
- A UDP_REP whose payload length is `MAX_UDP_PAYLOAD` or smaller still decodes to the same `xid`, host, port, and bytes.
- `cargo test -p bibavpn` passes, including existing UDP mux tests that call `decode_udp_rep`.

## Non-goals

- Hardening other inner opcodes, padded-frame size, or AEAD ciphertext length.
- Making `decode_udp_req` check length before `to_vec()` (same allocation pattern; not this issue).
- Changing how the server builds replies or how the client emits SOCKS UDP datagrams beyond what a failing `decode_udp_rep` already prevents.
