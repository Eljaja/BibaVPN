VERDICT: PASS

- Encode always writes outer blob v2 (`version || salt(16) || m/t/p LE || nonce(12) || ct`) with Argon2id v0x13, OWASP defaults `19456/2/1`, random salt, and no BLAKE3 on that path.
- Decode is version-aware: v1 uses the private BLAKE3 helper; v2 parses recorded params, rejects `0` / over-cap values before Argon2, then decrypts; other versions return `invite: unsupported blob version`. Inner `InviteV1.v` is checked against `1`, not the outer byte.
- Public names, JSON schema, and file set stay in spec (`invite_uri.rs`, `bibavpn/Cargo.toml` + lockfile, `PROTOCOL.md` invite section only). No CLI, apps, proto-3, REALITY, or cover-traffic changes; no secrets added.
- Named tests are present and passed in `cargo test -p bibavpn`: v2 round-trip, wrong passphrase, v1 still decodes, unknown version `3`, v2 `m_kib` cap, and unchanged `old_minimal_json_still_parses`.
