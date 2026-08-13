# Implementation notes

## Summary

Hardened the desktop split-tunnel bypass list fetch/apply boundary per SPEC.md:

- **HTTPS-only** `BIBA_BYPASS_DOMAINS_URL` (runtime + `build.rs` + CI script); non-HTTPS URLs refused with a `bibavpn_desktop` log line and no GET.
- **Pinned Ed25519 pubkey** via `BIBA_BYPASS_DOMAINS_PUBKEY` (hex 32-byte key); network, disk cache, and non-empty embed all require verify-before-parse.
- **Detached `.sig` companion** fetched alongside JSON (`path.sig` before query string).
- **Signed disk cache** stores `raw_body` + `signature`; legacy/tampered caches deleted and not applied.
- **Embedded list** applied only when non-empty presets and a valid signature verify; empty placeholder stays unsigned.
- **Fail closed**: unsigned/tampered payloads rejected; in-memory known-good kept; unsigned per-preset fallback removed.
- **Logging**: successful `apply_presets` logs `source`, `presets`, and `domains` counts under `bibavpn_desktop`.

## Files changed

| File | Change |
|------|--------|
| `apps/bibavpn-desktop/src-tauri/src/bypass_domains.rs` | URL/pubkey checks, Ed25519 verify, signed cache, apply logging, unit tests |
| `apps/bibavpn-desktop/src-tauri/Cargo.toml` | `ed25519-dalek` v2 + `base64` |
| `apps/bibavpn-desktop/src-tauri/build.rs` | HTTPS-only URL bake, pubkey bake, embed `.sig` |
| `.github/scripts/ci-fetch-bypass-domains.sh` | HTTPS-only GET; fetch `.sig` when pubkey set |
| `apps/bibavpn-desktop/src-tauri/embedded/README.md` | Document https + pubkey + detached sig |

## Tests

```
cargo test -p bibavpn-desktop --locked bypass_domains  → 12 passed
cargo test -p bibavpn-desktop --locked                 → 26 passed
```

Full output in `TEST.log`.
