# Spec

## Summary

Stop the desktop app from treating `bibavpn://import?token=…&base_url=…` as a trusted control-plane address. Validate `base_url` (HTTPS only, no userinfo/path tricks, host must match a compile-time allowlist) **before** any HTTP request, then require an explicit in-app confirmation that names the control-plane host (and the VPN host from the payload) **before** writing invite/passphrase/server fields to disk.

Today `parse_import_deeplink` in `apps/bibavpn-desktop/src-tauri/src/lib.rs` only checks that the deeplink host is `import`. `control_plane_client::redeem_import` POSTs the token to `{base_url}/api/v1/client/import` verbatim (including `http://`). `import_control_plane_payload` then applies `invite_uri`, `invite_passphrase`, `server_public_host` / invite fields and persists. A malicious page, chat message, or QR can harvest the token and silently repoint the VPN.

This is a **desktop-app** change only. Smallest shippable slice: client-side URL pinning + confirm-before-apply. Server-side token lifetime stays out of scope.

## In scope

1. **Strict `base_url` validation** (pure function, unit-tested), called from `redeem_import` / `handle_import_deeplink` **before** `ureq` runs:
   - Parse with the `url` crate (already in the workspace lockfile; add it as a direct dep of `bibavpn-desktop`).
   - Scheme must be `https` (case-insensitive). Reject `http`, scheme-relative (`//host`), missing scheme, `javascript:`, `data:`, `file:`, `ws:`, and anything else.
   - Reject any URL with **userinfo** (`https://evil@good.example`, `https://evil:pw@good.example`).
   - Reject query, fragment, and a path other than empty or `/` so the POST is always `{origin}/api/v1/client/import`.
   - Reject empty host. Compare host via `Url::host_str()` (IDNA / punycode form), case-insensitive.
   - Canonicalize to `https://host` or `https://host:port` (omit port when it is 443). Return that origin string; use it for the POST, not the raw query value.

2. **Host allowlist** (union of both sources; either match is enough):
   - **Compile-time / runtime origin** of `BIBA_BYPASS_DOMAINS_URL` — same `option_env!` + `std::env::var` pattern as `bypass_domains::bypass_domains_url()` (do not hardcode a production hostname in source). Extract scheme+host+port from that URL; it must itself be `https`.
   - **Already-configured origins** from every non-empty `TunnelProfile.control_plane_base_url` in the saved config (so a re-import to a CP the user already used still works if the env var is unset in a local build).
   - If the allowlist is empty, reject the import with a clear error (official CI builds bake `BIBA_BYPASS_DOMAINS_URL`; unofficial builds must not accept an arbitrary host).
   - Origin match is exact: `https://good.example.evil.com` and `https://good.example:4443` (when allowlist is `:443`) are rejected.

3. **No request on failure.** Validation errors return a short Russian/English-safe operator message (match existing `control plane:` / `Неверная ссылка импорта` style). Do not log the token. Set `last_error` the same way the current deeplink handler already does.

4. **Confirm before persist.** After a successful redeem, do **not** call `import_control_plane_payload` / `persist_cfg` until the user confirms.
   - Store the validated origin + `ImportPayload` as **in-memory pending state** on `AppState` (not disk).
   - Show the main window, emit a pending event (e.g. `control-plane-import-pending`) with **control-plane host**, `display_name` / `server_name`, and `server_public_host`:`host_port`.
   - In-app modal (dark UI, `i18n.js` ru+en): “Import config from `{cp_host}`? VPN server will be `{server_public_host}`.” Confirm / Cancel.
   - Confirm command applies payload + persists + emits existing `control-plane-import` + `vpn-state`. Cancel drops pending state and does not write config.
   - On UI mount (startup deeplink can fire before React is listening), a `get_pending_import` command re-reads pending state so the modal still appears.
   - A new deeplink replaces pending state only after validation; never persist the previous pending payload.

5. Keep `parse_import_deeplink` extracting `token` + `base_url` from the `bibavpn://import?…` query; **validation of `base_url` is a separate step**, not a reason to accept a malformed deeplink as “parsed OK”.

## Out of scope

- Control-plane server: single-use / short-lived import tokens, rate limits, or API changes (different repo).
- Pinning **only** to the active profile’s `control_plane_base_url` as the sole policy (breaks first-time import when that field is empty).
- Hardcoding `biba-llc.com` or any production host in the open tree.
- Tunnel / proto-3 / `bibavpn` crate / `biba` crate / JNI / iOS FFI / camouflage HTTP.
- Changing invite URI (`biba://`) encoding or `decode_invite_v1`.
- New e2e / Playwright / deeplink OS-integration harness.
- `tauri-plugin-dialog` native OS boxes (startup-safe confirm is the in-app pending modal so Android/iOS/desktop share one UI).

## Files to change

- `apps/bibavpn-desktop/src-tauri/src/control_plane_client.rs` — add `validate_control_plane_base_url(base_url, allowed_origins) -> Result<String, String>`; call it at the start of `redeem_import` (or have the handler validate then pass the canonical origin). Expand unit tests here (preferred: keep URL tests next to the HTTP client).
- `apps/bibavpn-desktop/src-tauri/src/lib.rs` — `handle_import_deeplink`: validate → redeem → pending state (no persist); new commands `get_pending_import`, `confirm_pending_import`, `cancel_pending_import`; extend `deeplink_tests`.
- `apps/bibavpn-desktop/src-tauri/src/bypass_domains.rs` — reuse `bypass_domains_url()` only; do not duplicate env loading. A tiny helper to turn that URL into an allowlist origin may live in `control_plane_client` to keep bypass-list fetching unchanged.
- `apps/bibavpn-desktop/src-tauri/Cargo.toml` — direct `url` dependency.
- `apps/bibavpn-desktop/ui/src/App.jsx` (and `i18n.js`) — pending-import modal; listen for `control-plane-import-pending`; poll/get pending on mount.
- `apps/bibavpn-desktop/local.env.example` — one-line note that import `base_url` must be HTTPS on the same host as `BIBA_BYPASS_DOMAINS_URL`.
- `apps/bibavpn-desktop/src-tauri/src/config.rs` — only if a small helper is needed to collect `control_plane_base_url` origins from `SavedConfig`; **do not** change `import_control_plane_payload` wire mapping except to keep using the **canonical** origin for `p.control_plane_base_url`.

Do not touch `bibavpn/` or `biba/`.

## Tests

Run from repo root (same command CI uses for this crate in `.github/workflows/test.yml`):

```bash
cargo test -p bibavpn-desktop --locked
```

Add/extend unit tests in `control_plane_client.rs` and `lib.rs` (`deeplink_tests`). Do **not** add a new test harness. Cover at least:

**Accept**

- `https://cp.example.com` and `https://cp.example.com/` when `cp.example.com` is allowlisted.
- `HTTPS://CP.EXAMPLE.COM` (scheme/host case).
- Existing profile `control_plane_base_url` origin when compile-time env is unset (pass origins in as a function argument; do not rely on CI secrets in unit tests).

**Reject (no HTTP, clear `Err`)**

- `http://cp.example.com`
- `https://evil.example` when allowlist is `cp.example.com`
- `https://evil@cp.example.com` and `https://evil:pw@cp.example.com`
- scheme-relative `//cp.example.com`
- `https://cp.example.com.evil.com`
- `https://cp.example.com/extra` and `https://cp.example.com?x=1`
- empty / whitespace `base_url`
- empty allowlist

Keep `parse_import_deeplink_ok` working for a percent-encoded `https://` URL. Add a test that `redeem_import` returns `Err` for `http://…` **without** needing a live server (fail in validation before `ureq`). Confirmation: unit-test that applying pending state is a separate step from redeem (e.g. confirm/cancel helpers or documented command behavior); do not pop a GUI in `cargo test`.

Do **not** run `cargo test -p bibavpn` unless something under `bibavpn/` is changed (it should not be).

## Acceptance criteria

- `http://` and non-allowlisted hosts are rejected with a clear error and **no** control-plane HTTP request.
- Userinfo, scheme-relative, and extra-path/query `base_url` values are rejected even when the “looks like” host is allowlisted.
- Allowlisted HTTPS origin: redeem may run; config is **not** written until the user confirms a modal that names the control-plane host (and the VPN host from the payload).
- Cancel leaves saved profiles unchanged.
- `cargo test -p bibavpn-desktop --locked` passes, including the new accepted/rejected URL cases.

## Non-goals

- Making import tokens single-use on the server.
- Trusting the control-plane JSON less than today beyond the confirm step (no extra invite signature scheme).
- Allowing operators to type an arbitrary extra allowlist in Settings.
- Changing `bibavpn://` scheme registration or the `import` deeplink host.
- Metrics, logging of tokens/passphrases, or new `bibavpn_*` tracing targets.
