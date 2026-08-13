# Implementation

## Summary

Fixed a pre-HELLO junk accounting gap: binary frames starting with `0x03` that fail `parse_hello_v3` are now counted against the same frame/byte caps as empty or non-HELLO noise, instead of being ignored until `--handshake-timeout-secs`.

## Changes

### `bibavpn/src/server_limits.rs`

- Added `MAX_PRE_HELLO_FRAMES`, `MAX_PRE_HELLO_BYTES`, `PRE_HELLO_CAP_ERR`.
- Added `PreHelloJunkTracker` and pure helper `account_pre_hello_binary`:
  - `Ok(Some(client_random))` — well-formed v3 HELLO (counters unchanged).
  - `Ok(None)` — junk counted (empty, wrong tag, malformed `0x03`, length/pad errors).
  - `Err` — cap exceeded (`too much pre-handshake data before v3 HELLO`).
- Added seven unit tests covering malformed-HELLO floods, byte cap, well-formed HELLO, junk-then-HELLO, and non-`0x03` regression.

### `bibavpn/src/bin/server.rs`

- `server_handshake_v3` now calls `account_pre_hello_binary` for every pre-AUTH binary frame instead of the split `first-byte != 0x03` / `parse_hello_v3` `continue` path.

## Tests

```bash
cargo test -p bibavpn
```

Result: **193 tests passed** (174 lib + 19 integration/bin), 0 failed.

## Wire format

No change to HELLO/ACK layout or client noise behavior.
