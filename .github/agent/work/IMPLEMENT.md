# Implementation notes

## Summary

Implemented Argon2id outer blob v2 for `biba://` invites per SPEC.md.

## Changes

- `bibavpn/Cargo.toml` — added `argon2` dependency.
- `bibavpn/src/invite_uri.rs` — v2 encode (always), dual-version decode (v1 BLAKE3 + v2 Argon2id), param caps, tests.
- `PROTOCOL.md` — documented v1/v2 outer blob layouts and KDFs.

## Tests

`cargo test -p bibavpn` — **passed** (all 171 lib/integration tests + invite_uri unit tests).
