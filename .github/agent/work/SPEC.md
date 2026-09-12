# Spec

## Summary

Issue #46 is a three-item wishlist. This PR ships only the first item: switch `biba://` invite sealing from a fast BLAKE3 KDF to **Argon2id** (memory-hard, per-blob salt + recorded params), bump the **outer** blob version, and keep decoding existing v1 invites.

Today `encode_invite_v1` / `decode_invite_v1` in `bibavpn/src/invite_uri.rs` seal `InviteV1` JSON with ChaCha20-Poly1305. The key is `blake3::derive_key("bibavpn.invite.uri.v1", passphrase)` — cheap to brute-force offline if the URI leaks. The wire is `version(1) || nonce(12) || ciphertext` with `BLOB_VERSION = 1`. Decode rejects any other first byte. After decrypt, `invite.v` is compared to `BLOB_VERSION`; those two version spaces must be split when the outer byte becomes `2`, because inner JSON `InviteV1.v` stays `1`.

Callers (`bibavpn-server --print-invite-uri`, `bibavpn-mint-invite`, `bibavpn-client --from-invite`, JNI/FFI/desktop via `decode_invite_v1`) do not need signature changes.

## In scope

- Add the `argon2` crate to `bibavpn/Cargo.toml` (RustCrypto `argon2`, Argon2id, version 0x13).
- **Encode always writes blob v2:**
  - `version: u8 = 2`
  - `salt: 16` random bytes
  - `m_kib: u32` LE (Argon2 memory in KiB)
  - `t_cost: u32` LE
  - `p_cost: u32` LE
  - `nonce: 12` random bytes
  - ChaCha20-Poly1305 ciphertext of the same `InviteV1` JSON as today
- **Default encode params** (OWASP interactive; one-shot decode on desktop/Android/iOS): `m_kib = 19456` (19 MiB), `t_cost = 2`, `p_cost = 1`, output 32 bytes. Record these in the blob so they can change later without a new version.
- **KDF:** Argon2id(password = passphrase bytes, salt = blob salt, recorded params) → 32-byte ChaCha20-Poly1305 key. Do not also run the old BLAKE3 derive on v2.
- **Decode is version-aware:**
  - `1`: existing layout and `blake3::derive_key("bibavpn.invite.uri.v1", passphrase)` (keep a private v1 helper).
  - `2`: parse salt + params + nonce + ct; derive with Argon2id; decrypt.
  - anything else: `invite: unsupported blob version`.
- After decrypt, require `invite.v == 1` (JSON schema), **not** equality with the outer blob version.
- On v2 decode, reject params that exceed a hard cap to avoid memory DoS from a crafted URI: `m_kib > 65536` or `t_cost > 8` or `p_cost > 4` or any of `m_kib` / `t_cost` / `p_cost` is `0`.
- Keep public names `encode_invite_v1` / `decode_invite_v1` / `InviteV1`.
- Wrong passphrase or corrupt ciphertext: same user-facing error as today (`invite: bad passphrase or corrupted blob`).
- Update the `invite_uri.rs` module comment and the **Encrypted invite `biba://`** section in `PROTOCOL.md` so the v1/v2 blob layouts and KDFs are documented. Do not describe proto-3 tunnel changes.

## Out of scope

- Item 2: post-quantum hybrid handshake (X25519 + ML-KEM-768) in `reality.rs` / `crypto_layer.rs` / `protocol.rs`.
- Item 3: Poisson / exponential cover-traffic timing in `decoy_traffic.rs` / `stealth_v12.rs`.
- Changing `InviteV1` JSON fields or inner `v`.
- New CLI flags for Argon2 params, passphrase stretching, or “mint v1”.
- Re-encoding or migrating stored invites (old URIs keep working until the user remints).
- Copying code from qeli.
- App / JNI / FFI / Tauri UI changes (they already call `decode_invite_v1`).
- Proto-3 session KDF, REALITY MAC, or any on-tunnel wire change.

## Files to change

- `bibavpn/Cargo.toml` — add `argon2`.
- `bibavpn/src/invite_uri.rs` — v2 encode, dual-version decode, tests, module docs.
- `PROTOCOL.md` — Encrypted invite section: v2 layout + Argon2id; note v1 BLAKE3 still decodes.

No changes to `mint_invite.rs`, `bin/server.rs`, `bin/client.rs`, `start_json_config.rs`, or `apps/*` unless a compile break forces a one-line import fix (none expected).

## Tests

Add/extend unit tests in `bibavpn/src/invite_uri.rs` (`#[cfg(test)]`):

- **v2 round-trip:** `encode_invite_v1` then `decode_invite_v1` with the same passphrase; payloads equal; URI still starts with `biba://`; decoded raw blob first byte is `2`.
- **wrong passphrase:** decode of a fresh v2 URI with a different passphrase fails.
- **v1 still decodes:** build a v1 blob in the test with the existing BLAKE3 helper (`version=1 || nonce || ct`) and `decode_invite_v1` succeeds. Do not require a checked-in URI string that would go stale.
- **unknown version:** first byte `3` (otherwise well-formed) → unsupported version.
- **v2 param cap:** a v2 header with `m_kib` above the cap fails before Argon2 runs.
- Keep `old_minimal_json_still_parses` as-is.

Existing `start_json_config` invite test keeps working because it uses encode+decode.

Run:

```bash
cargo test -p bibavpn
```

That covers `invite_uri` and the JSON-start invite path. Do not add a new harness. `biba` is not touched, so do not add `-p biba`.

## Acceptance criteria

- New invites from `encode_invite_v1` (server `--print-invite-uri`, `bibavpn-mint-invite`) are blob v2 and use Argon2id with a random 16-byte salt and recorded `m`/`t`/`p`.
- A v1 blob produced with the current BLAKE3 KDF still decodes with the correct passphrase.
- Wrong passphrase fails closed; unknown blob versions fail closed; oversized Argon2 params fail closed.
- Inner `InviteV1` JSON is unchanged (`v` remains `1`).
- `cargo test -p bibavpn` passes.
- `PROTOCOL.md` documents both blob versions.

## Non-goals

- ML-KEM / hybrid handshake, proto-3 or REALITY key-agreement changes.
- Poisson cover traffic or stealth-profile timing changes.
- Making Argon2 params operator-configurable in this PR.
- Dropping v1 decode.
- Changing how passphrases are collected or displayed in apps.
- Benchmarking handshake overhead (that belongs to the PQ item).
