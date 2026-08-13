# Spec

## Summary

In `server_handshake_v3`, pre-HELLO binary frames are counted against `MAX_PRE_HELLO_FRAMES` / `MAX_PRE_HELLO_BYTES` only when they are empty or do not start with `V3_HELLO_TAG` (`0x03`). A frame that starts with `0x03` but fails `parse_hello_v3` is `continue`’d with no junk accounting, so an attacker can hold a session slot until `--handshake-timeout-secs` with cheap structurally invalid HELLO-shaped payloads.

This PR treats every binary that is not a well-formed v3 HELLO (including `0x03 || garbage`) as pre-HELLO junk: increment frame/byte counters and bail at the existing caps. A single well-formed HELLO still proceeds to ACK + AUTH. No wire-format change.

## In scope

- Collapse the pre-HELLO binary branch so **any** frame that `parse_hello_v3` rejects is counted as junk (empty, wrong first byte, too short, `pad_len` > `V3_HELLO_PAD_MAX`, or length ≠ `V3_HELLO_MIN_WIRE_LEN + pad_len`).
- Keep the existing caps and bail string: `MAX_PRE_HELLO_FRAMES = 256`, `MAX_PRE_HELLO_BYTES = 256 * 1024`, error `"too much pre-handshake data before v3 HELLO"`.
- Extract a small pure helper (e.g. `account_pre_hello_binary` in `server_limits.rs`) that returns `Ok(Some(client_random))` for a well-formed HELLO without touching counters, `Ok(None)` after counting junk, and `Err` when a cap is exceeded. Wire `server_handshake_v3` to that helper so the cap is unit-testable without a WebSocket.
- Unit tests: flood of `0x03 || garbage` hits the cap; one `build_hello_v3()` frame is accepted with counters unchanged; non-`0x03` junk still counts (regression).

## Out of scope

- Calling `auth.record_failure` after N malformed HELLOs (issue listed this as optional). Pre-HELLO junk already bails without a rate-limit record; do not add a new failure path here.
- Changing AUTH-phase `PreAuthBudget` / `PreAuthBudgetTracker` (`server_wait_v3_auth`, `ws_auth.rs`).
- Unifying pre-HELLO caps with `--handshake-max-junk-bytes` / the `pre_auth` argument already passed into `server_handshake_v3` (today the loop ignores it).
- REALITY follow-up `server_handshake_v3_after_first_hello` (that path parses once and fails the session; it does not loop).
- HELLO/ACK layout, `parse_hello_v3` rules, `PROTOCOL.md`, client noise (`--junk-frames` / `--early-ws-frames`), new CLI flags.

## Files to change

- `bibavpn/src/server_limits.rs` — add `account_pre_hello_binary` (or equivalent) next to `PreAuthBudgetTracker`; add `#[cfg(test)]` cases for the malformed-HELLO cap.
- `bibavpn/src/bin/server.rs` — in `server_handshake_v3` (~1458), replace the `first-byte != V3_HELLO_TAG` / `parse_hello_v3` `Err(_) => continue` split with the helper. Leave ACK, AUTH, and timeout/`record_failure` on timeout as they are.

## Tests

- Add unit tests in `bibavpn/src/server_limits.rs` (same module as the helper):
  - Malformed HELLO-shaped frames (`[0x03]` plus short or length-inconsistent garbage) increment junk frames/bytes and return `Ok(None)`.
  - `max_frames + 1` such frames (use a small cap in the test, e.g. 3, plus a case at the production 256) returns `Err` whose message contains `too much pre-handshake data before v3 HELLO`.
  - One oversized `0x03`-prefixed buffer exceeding `max_bytes` also returns `Err` (byte cap, not only frame cap).
  - `crypto_layer::build_hello_v3()` returns `Ok(Some(client_random))` matching the built random; counters stay at 0.
  - After some counted junk, a well-formed HELLO still returns `Ok(Some(_))` (junk before HELLO remains allowed under the cap).
  - A binary that does not start with `0x03` still counts as junk (existing behavior).
- Do not add a new e2e/WS harness. Existing `parse_hello_v3` tests in `crypto_layer.rs` stay as they are.

Run:

```bash
cargo test -p bibavpn
```

Optional before PR:

```bash
cargo clippy -p bibavpn -- -D warnings
```

## Acceptance criteria

- A flood of WebSocket binaries of the form `0x03 || garbage` is rejected by the pre-HELLO junk cap (frame or byte), with the existing bail message, without waiting for `--handshake-timeout-secs`.
- Empty / non-`0x03` pre-HELLO noise is still counted against the same caps.
- One well-formed v3 HELLO (`build_hello_v3` / client handshake) still proceeds to ACK and `server_wait_v3_auth`.
- HELLO/ACK on-wire layout is unchanged.
- `cargo test -p bibavpn` passes, including the new malformed-HELLO cap tests.

## Non-goals

- Timestamp anti-replay on a valid handshake (not this issue; that is #31).
- New auth-ban / per-IP malformed-HELLO counters or CLI knobs.
- Closing the session faster than the junk cap via a dedicated malformed-HELLO limit.
- Docs, invite JSON, JNI/Tauri, REALITY AUTH, or proto-3 KDF/domain changes.
