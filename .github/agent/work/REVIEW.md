VERDICT: PASS

- HELLO v3 is 65 bytes (`version=3 || ephemeral:32 || short_id:8 || unix_secs BE || nonce:16`); `SERVER_HELLO` / AUTH frame layouts are unchanged except the version byte; `REALITY_VERSION` is 3.
- AUTH MAC transcript is `client_ephemeral_pub || server_pub || unix_secs_be || nonce` with derive-key context `bibavpn reality client-auth v2`; confirm-MAC input is unchanged. MAC uses the HELLO fields parsed once (no re-read).
- Server rejects short/wrong-version HELLO and timestamp skew (`|now - unix_secs| > max_time_diff`) before X25519; replay cache insert runs only after AUTH MAC verifies.
- Process-wide `Arc<Mutex<…>>` cache stores `(nonce, hello_unix_secs)`, expires with `max_time_diff`, caps at 65536 (evict oldest timestamp). Built once in `bibavpn-server` when REALITY is on. CLI `--reality-max-time-diff-secs` default 90, range `1..=3600`; `max_time_diff` is no longer hardcoded to 0. Client sends `SystemTime` + `OsRng` nonce; no client flag.
- Named unit and integration tests are present (wire/round-trip, window, MAC binding, cache duplicate/expiry/cap, happy path, captured-byte replay, stale vs in-window skew, wrong-token, missing AUTH). `TEST.log`: `cargo test -p bibavpn` 171 lib tests + `reality_handshake` 7/7 passed. Diff stays in the spec files; no proto-3 PSK AUTH, invite JSON, or secrets.
