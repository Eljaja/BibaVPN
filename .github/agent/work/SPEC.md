# Spec

## Summary

Wire up unused `RealityServerConfig.max_time_diff` so a captured REALITY handshake cannot be replayed.

Today a REALITY client HELLO is `[version:1][ephemeral_x25519:32][short_id:8]` (`REALITY_VERSION = 2`). The mandatory AUTH MAC covers only the two public keys. An on-path observer can resend the same HELLO + AUTH bytes and the server derives the same X25519 shared secret and accepts the MAC.

This PR extends the REALITY **client HELLO** with a unix timestamp and a random nonce, binds both into the AUTH MAC, rejects HELLO timestamps outside `±max_time_diff`, and remembers authenticated nonces for that window. Default window is **90 seconds**, exposed as a server flag. This is a breaking REALITY-path change: bump `REALITY_VERSION` to **3**.

Do not change proto-3 PSK `AUTH` in this PR.

## In scope

1. **HELLO v3 layout** (fixed 65 bytes, big-endian timestamp):

   `[version:1=0x03][client_ephemeral_x25519:32][short_id:8][unix_secs:u64 BE][nonce:16]`

   `SERVER_HELLO` layout stays `[version:1][server_pub:32][confirm_mac:32]`; only the version byte becomes `3`. AUTH frame layout stays `[version:1][0xa1][mac:32]`; version byte becomes `3`.

2. **Bind freshness into AUTH MAC.** Extend `reality_client_auth_mac` so the keyed BLAKE3 transcript is `client_ephemeral_pub || server_pub || unix_secs_be || nonce`. Bump the derive-key context from `bibavpn reality client-auth v1` to `bibavpn reality client-auth v2`. Confirm MAC / SERVER_HELLO transcript is unchanged aside from the version byte.

3. **Server checks (in `server_handshake_reality`):**
   - After parsing HELLO: reject wrong version / short frame; reject if `|now_unix_secs - unix_secs| > max_time_diff` with a clear error (mention timestamp / window). Do this **before** X25519.
   - After AUTH MAC verifies: if the 16-byte nonce is already in the replay cache, reject with a clear replay error; otherwise insert. **Do not** insert on failed AUTH (unauthenticated HELLO must not fill the cache).
   - Timestamp and nonce values used for the MAC **must** be the ones parsed from this HELLO (no re-read).

4. **Replay cache:** process-wide, shared by all REALITY sessions (`Arc` + mutex). Store `(nonce, hello_unix_secs)`. On each check, drop entries with `hello_unix_secs + max_time_diff < now` (a replay after that would fail the timestamp check anyway). Cap at **65536** entries; if still full after expiry, evict the oldest `hello_unix_secs` then insert. Construct once in `bibavpn-server` when REALITY is enabled; pass into `server_handshake_reality`.

5. **Default and CLI.** Default `max_time_diff` is **90** seconds (not `0`). Add `bibavpn-server --reality-max-time-diff-secs` (u64, default 90, allowed range **1..=3600**). Reject `0` at clap / startup — do not treat `0` as “disable”. Set `RealityServerConfig.max_time_diff` from this flag. Client always sends `SystemTime` unix seconds and 16 random bytes (`OsRng`); no client flag.

6. **Docs:** `PROTOCOL.md` REALITY section (HELLO bytes, version 3, MAC transcript, incompatibility with v2), `AGENTS.md` version note, `README.md` one-line CLI mention next to the other REALITY flags.

## Out of scope

- Proto-3 PSK sealed `AUTH` timestamp / nonce (wishlist leftover; separate PR).
- Changing `SERVER_HELLO` fields or `reality_confirm_mac` input.
- Persisting the nonce cache across process restart.
- Client / invite JSON field for `max_time_diff`.
- Disabling anti-replay (`max_time_diff = 0`).
- NTP / clock-sync helpers; operators must have roughly aligned unix time.
- Xray TLS ClientHello REALITY, JNI/Tauri/UI toggles, metrics counters for replays.

## Files to change

- `bibavpn/src/reality.rs` — `REALITY_VERSION = 3`; HELLO encode/decode; AUTH MAC transcript + context string; `RealityReplayCache`; enforce window + nonce in `server_handshake_reality`; client `reality_client_exchange_verify` / `encode_client_hello`; existing `#[cfg(test)]` layout and MAC tests.
- `bibavpn/src/lib.rs` — re-export new HELLO helpers / cache type if the integration test needs them (keep the public surface small).
- `bibavpn/src/bin/server.rs` — `--reality-max-time-diff-secs`; stop hardcoding `max_time_diff: 0`; one shared cache; pass it into `server_handshake_reality`.
- `bibavpn/tests/reality_handshake.rs` — happy path with v3 HELLO; replay of captured bytes; skew inside vs outside window; `max_time_diff: 90` (or the value under test) instead of `0`.
- `PROTOCOL.md`, `AGENTS.md`, `README.md` — wire + CLI as above.

Call-site note: `server_handshake_reality` is only used from `bin/server.rs` and `tests/reality_handshake.rs`. `encode_client_hello` / `reality_client_auth_mac` call sites in this crate must be updated to the new signatures.

Suggested helpers (names can vary, behavior must not):

- `encode_client_hello(short_id, client_pubkey, unix_secs, nonce: &[u8; 16]) -> Vec<u8>`
- `decode_client_hello(&[u8]) -> Result<…>` (version, pubkey, short_id, unix_secs, nonce)
- `reality_timestamp_in_window(now: u64, unix_secs: u64, max_time_diff: u64) -> Result<()>`
- `RealityReplayCache::check_and_insert(nonce, hello_unix_secs, now, max_time_diff) -> Result<()>`

Inject `now` in unit tests; production handshake uses current unix seconds.

## Tests

Run:

```bash
cargo test -p bibavpn
cargo test -p bibavpn --test reality_handshake
```

Add/extend tests in `bibavpn/src/reality.rs` (`#[cfg(test)]`) and `bibavpn/tests/reality_handshake.rs`. No new harness.

Unit (`reality.rs`):

- HELLO wire is 65 bytes, version `3`, round-trip decode.
- Short / wrong-version HELLO fails.
- `reality_timestamp_in_window`: `|delta| <= max_time_diff` ok; `max_time_diff + 1` both past and future fail.
- AUTH MAC matches for the same `(token, keys, unix_secs, nonce)` and differs if timestamp or nonce changes.
- Replay cache: first insert ok; same nonce rejected; nonce accepted again after `hello_unix_secs + max_time_diff < now`; inserting past the cap does not grow unbounded (len ≤ 65536).
- Existing confirm-MAC / wrong-token / cross-session AUTH tests updated to the new MAC signature.

Integration (`reality_handshake.rs`):

- Current happy path still succeeds (client `reality_client_exchange_verify` vs `server_handshake_reality`) with a shared cache and `max_time_diff: 90`.
- Capture HELLO + AUTH bytes from a successful handshake (or build them with `encode_client_hello` / `encode_client_auth`); send the **same bytes** on a second connection to a server that still holds the cache → server `Err` (replay).
- HELLO with `unix_secs = now - max_time_diff - 1` → server `Err` whose message is clearly about time / window; skew of `max_time_diff` (or a few seconds inside it) still succeeds.
- Existing wrong-token and missing-AUTH cases still fail.

## Acceptance criteria

- A replayed REALITY handshake (exact captured HELLO + AUTH resent while the nonce is still in the window) is rejected by the server.
- Clock skew with `|now - unix_secs| <= max_time_diff` succeeds; outside that window fails with a clear timestamp/window error (no token/PSK in logs).
- Seen-nonce set is a sliding window, expires with `max_time_diff`, and is capped (65536).
- Default window is 90s via `--reality-max-time-diff-secs`; `RealityServerConfig.max_time_diff` is no longer stuck at `0` and is actually read.
- v2 REALITY peers fail immediately on version mismatch (`REALITY_VERSION = 3`).
- `cargo test -p bibavpn` and `cargo test -p bibavpn --test reality_handshake` pass.

## Non-goals

- Anti-replay for proto-3 PSK `AUTH` / `HELLO`.
- Compatibility with `REALITY_VERSION` 2 on the REALITY path.
- Surviving nonce-cache loss on server restart (a replay whose timestamp is still in-window could succeed until the new cache fills; accepted limitation).
- Hiding REALITY as Xray TLS-hook REALITY, or any DPI/fingerprint work.
- New metrics, log targets, or invite fields.
