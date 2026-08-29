# Embedded split-tunnel / bypass-domains list

CI runs [`.github/scripts/ci-fetch-bypass-domains.sh`](../../../../.github/scripts/ci-fetch-bypass-domains.sh)
before building desktop / Android clients. That script downloads the JSON from the
`BIBA_BYPASS_DOMAINS_URL` repository secret into `bypass_domains.json` (gitignored).

## HTTPS + signature

- `BIBA_BYPASS_DOMAINS_URL` must be **`https://`** with a non-empty host. Non-HTTPS URLs are
  refused at build time, in the CI fetch script, and at runtime (no HTTP GET).
- `BIBA_BYPASS_DOMAINS_PUBKEY` is the **hex-encoded 32-byte Ed25519 public key** used to verify
  detached signatures. Set it in CI / local `.env` (do not commit a production key).
- The origin serves JSON and a companion **detached signature** at the same path with `.sig`
  appended before the query string (`https://host/api?x=1` → `https://host/api.sig?x=1`).
  Signatures are 64-byte Ed25519 over the **raw JSON body** (unpadded base64 or raw 64 bytes).

When `BIBA_BYPASS_DOMAINS_PUBKEY` is set, CI also fetches `bypass_domains.json.sig` next to the JSON.

`build.rs` copies both files into `OUT_DIR` so `bypass_domains.rs` can `include_str!` them at compile
time. A non-empty embedded list is applied only when the signature verifies with the pinned key.
The empty placeholder (`presets: []`) stays unsigned and does not activate split-tunnel presets.

Local builds without the secret still compile; split-tunnel presets stay empty until a verified
runtime fetch succeeds.
