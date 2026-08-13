VERDICT: PASS

- `account_pre_hello_binary` counts every `parse_hello_v3` rejection (empty, wrong tag, short/`0x03||garbage`) against the existing 256 / 256 KiB caps and bails with `too much pre-handshake data before v3 HELLO`.
- `server_handshake_v3` uses that helper; ACK, AUTH, timeout `record_failure`, `PreAuthBudget`, and `server_handshake_v3_after_first_hello` are unchanged. No wire-format, CLI, or extra auth-ban path.
- Named unit tests in `server_limits.rs` cover malformed HELLO junk, small and production frame caps, byte cap, `build_hello_v3` with counters at 0, junk-then-HELLO, and non-`0x03` regression. `cargo test -p bibavpn` passed (including those tests). No secrets in the diff.
