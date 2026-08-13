# Spec

## Summary

The desktop split-tunnel bypass list is loaded from `BIBA_BYPASS_DOMAINS_URL` (runtime or `build.rs` rustc-env), a disk cache, or a compile-time embed, then applied with no authenticity check. A MITM on `http://`, a hostile origin, or a rewritten cache file can choose which destinations leave the tunnel.

This PR hardens **only the fetch/apply boundary** in `bibavpn-desktop`: require `https`, verify a detached Ed25519 signature with a pinned public key before any list is applied (network, disk cache, and non-empty embed), drop a bad cache file, keep the previous known-good set, and log source + preset count on every successful apply.

Control-plane signing is a separate repo and is **not** implemented here. Tests mint their own keypair. Until the origin serves a matching `.sig` and CI/runtime has `BIBA_BYPASS_DOMAINS_PUBKEY`, a configured URL must fail closed (no unsigned remote/cache/embed apply).

## In scope

1. **HTTPS-only URL.** `bypass_domains_url()` (and `build.rs` baking of `BIBA_BYPASS_DOMAINS_URL`) must accept only `https://` with a non-empty host. Reject `http://`, `file:`, `data:`, empty host, and other schemes **before** any `ureq` GET. Log one clear `bibavpn_desktop` line (no request). The internal sentinel `embedded://bypass_domains` stays local-only and is never fetched.
2. **Pinned Ed25519 public key.** Same env pattern as the URL: `BIBA_BYPASS_DOMAINS_PUBKEY` (hex-encoded 32-byte key), runtime override then `build.rs` `cargo:rustc-env`. Do not commit a production key. If a remote URL is set and no pubkey is available, refuse network fetch and refuse disk-cache apply; log and keep in-memory known-good or empty embed-with-valid-sig / empty presets.
3. **Detached signature over raw body bytes.** After a 200 GET of the JSON body, fetch a companion signature URL: take the URL path, append `.sig`, keep any query string (`https://host/api?x=1` → `https://host/api.sig?x=1`). Body is the exact bytes verified; encoding is 64-byte Ed25519 signature as unpadded base64 **or** raw 64 bytes. Use `ed25519-dalek` on `bibavpn-desktop` only. Parse JSON only after verify succeeds.
4. **Untrusted disk cache.** Extend `BypassCacheFile` to store `raw_body` + `signature` (and keep `url` / TTL / `fetched_at_unix`). On load: verify signature over `raw_body` with the pinned key, then parse. On mismatch, missing sig, wrong URL, or verify failure: delete the cache file, do not apply, fall through. Never persist a body that failed verify. Legacy cache files without `raw_body`/`signature` are treated as mismatch.
5. **Embedded list.** Non-empty compile-time JSON is applied only if a matching signature was also embedded (CI writes `bypass_domains.json` **and** `bypass_domains.json.sig`; `build.rs` copies both into `OUT_DIR`). Empty placeholder (`presets: []`) stays unsigned and must not become an active bypass set.
6. **Fail closed + keep known-good.** Unsigned, tampered, or wrong-key payloads (network or disk) are rejected. If memory already has a verified set, keep it. Do not apply the bad list. The unsigned per-preset HTTP fallback (`fetch_remote_presets`) must not apply unverified bodies — skip that fallback rather than fetching N extra `.sig` files.
7. **Logging.** Every successful `apply_presets` logs `source` (https URL, `disk`, or `embedded`), `presets` count, and a `domains` count under target `bibavpn_desktop`. Do not log PSK/token/invite/PEM or the full domain list.
8. **CI fetch script.** `.github/scripts/ci-fetch-bypass-domains.sh` refuses a non-`https` URL (no GET). When `BIBA_BYPASS_DOMAINS_PUBKEY` is set, also fetch the `.sig` companion into `bypass_domains.json.sig` next to the JSON. Do not add a new verifier binary; cryptographic checks for the PR are the Rust unit tests plus runtime verify at embed load.

## Out of scope

- Control-plane (or any origin) signing service, key generation, key rotation, or minisign CLI packaging.
- Changing `bibavpn/src/domain_route.rs`, `split_tunnel.rs` routing, OS proxy bypass lists, or SOCKS `direct_bypass_relay` behavior.
- TLS certificate pinning / `--pin-cert` for the control-plane GET (webpki via existing `ureq` `tls` feature is enough for this slice).
- Per-preset `?preset=` fallback signatures; HTTP/2; new test harnesses or live-network tests against the real API.
- Hardcoding `BIBA_BYPASS_DOMAINS_URL` or a production pubkey in the open tree.
- JNI/iOS-only fetch paths (they consume the same desktop module / start JSON after this crate verifies).

## Files to change

- `apps/bibavpn-desktop/src-tauri/src/bypass_domains.rs` — URL scheme check, pubkey load, verify-before-parse, signed cache, apply logging, skip unsigned per-preset fallback, unit tests.
- `apps/bibavpn-desktop/src-tauri/Cargo.toml` — add `ed25519-dalek` (v2, same family as `x25519-dalek` in `bibavpn`).
- `apps/bibavpn-desktop/src-tauri/build.rs` — refuse to bake a non-https URL; bake `BIBA_BYPASS_DOMAINS_PUBKEY` when set; embed companion `.sig` when present.
- `.github/scripts/ci-fetch-bypass-domains.sh` — https-only GET; fetch `.sig` beside JSON when pubkey env is set.
- `apps/bibavpn-desktop/src-tauri/embedded/README.md` — document https + pubkey + detached `.sig` (no production secrets).

Do **not** change `bibavpn/src/domain_route.rs` or `apps/bibavpn-desktop/src-tauri/src/split_tunnel.rs` in this PR.

## Tests

Existing `#[cfg(test)]` module in `bypass_domains.rs` (CI already runs this crate). No new harness.

```bash
cargo test -p bibavpn-desktop --locked bypass_domains
cargo test -p bibavpn-desktop --locked
```

Add tests (generate an ephemeral Ed25519 keypair in-process; do not hit the network):

- `https://` URL with host is accepted; `http://`, `file://`, `https://` with empty host are rejected and must not call GET.
- Valid signature over a sample API JSON body verifies; parsed presets match.
- Tampered body (one byte flipped) with the original signature fails; wrong pubkey with a valid signature fails; missing signature fails.
- Disk-cache JSON with a valid `raw_body`+`signature` loads; the same cache with a flipped body or omitted signature is rejected (and would be deleted at runtime).
- `parse_sample_payload` / `parse_single_preset_payload` / `preset_fetch_url` keep passing.

Do not run `cargo test -p bibavpn` for this slice unless `domain_route.rs` is touched (it must not be).

## Acceptance criteria

- A non-`https` `BIBA_BYPASS_DOMAINS_URL` is refused with a clear `bibavpn_desktop` log line and no HTTP request (`build.rs` does not bake it; CI script does not GET it).
- An unsigned or tampered payload from the network is not applied; in-memory known-good (if any) is kept.
- A tampered or unsigned disk cache is not applied and the file is dropped.
- Unit tests cover valid signature, tampered body, wrong key, and cache rejection.
- `cargo test -p bibavpn-desktop --locked` passes.
- Successful apply logs source and preset count.

## Non-goals

- Making split-tunnel work against an unsigned production API (fail closed until the origin signs and the pubkey is supplied via env/CI).
- Authenticating the list with a symmetric MAC, minisign file format, or JSON-in-JSON envelope.
- Changing proto-3 wire format, server AUTH, or `domain_route::should_bypass` matching rules.
- UI for rotating keys or displaying the bypass list source in the Tauri front-end.
- Redirect-to-`http` hardening beyond rejecting the configured URL before GET.
