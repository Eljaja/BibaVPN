# Spec

## Summary

Stop shipping a public default tunnel token. `bibavpn-server`, `bibavpn-client`, and JSON start (`local_client_options_from_json_str`) currently fall back to `change-me` when `--token` / `token` is omitted, so a forgotten flag or a mobile JSON blob without `token` / `from_invite` authenticates with a well-known value. This PR removes that default, rejects empty and denylisted tokens at startup, requires `--psk` before listen unless REALITY is fully configured, and adds an explicit `--lab` escape hatch so local demos and `start.sh` still work.

This is not a wire-format change. AUTH, HELLO/ACK, and REALITY layouts stay the same.

## In scope

1. **Shared startup checks** in a new `bibavpn` module (e.g. `bibavpn/src/startup_secrets.rs`), used by both binaries and JSON start:
   - Token denylist (trim, then case-insensitive exact match): `change-me`, `changeme`, `test`. Empty / whitespace-only is denied.
   - Do not denylist `t`, `tok`, `test-token`, `testtok`, `wsl-test-token`, or `docker-compose-biba` (existing tests and compose values).
   - Never log the token or PSK. Errors may name the denylist literals.

2. **CLI (`bibavpn-server`, `bibavpn-client`)**:
   - Remove clap `default_value = "change-me"` from `--token` so `--help` does not advertise it.
   - `--token` is required unless `--from-invite` (client) or `--lab`.
   - New `--lab` (bool, default false): local demos only. When set, skip the token denylist; if `--token` is omitted, use `change-me`. Log one `WARN` on `bibavpn_security` that lab mode is enabled.
   - Client: keep `--token` conflicting with `--from-invite`. After invite merge, run the same denylist on the **resolved** token unless `--lab`.
   - Server: require a non-empty `--psk` at process start unless `--lab` **or** REALITY is fully configured (`--reality-target` and `--reality-private-key` both present and non-empty). Empty/whitespace PSK counts as missing.
   - Client: require a non-empty PSK at process start unless `--lab` **or** REALITY is fully configured (`--reality-target` and `--reality-public_key` both present and non-empty after invite merge). Today proto-3 still waits until the first WSS attempt (`local_client.rs`).
   - REALITY without PSK: allow start; log `WARN` that v3 HELLO / UDP mux still need `--psk`. Do not change the deferred `"Biba v3 requires server --psk"` path for that case.

3. **JSON start** (`start_json_config.rs`, Android `nativeStart` / desktop):
   - Delete the `"change-me"` fallback. No `token` and no invite → error.
   - After invite merge, if the resolved token is empty or denylisted → error. There is **no** JSON `lab` field and no denylist bypass.
   - After invite merge, if PSK is missing and REALITY is not fully configured (JSON/invite `reality_target` + `reality_public_key`) → error.
   - Invite-only JSON that already supplies a non-denylist token (and PSK or REALITY) keeps working. Desktop already omits `token` when using an invite; that path must keep working.

4. **Docs**: `AGENTS.md` and `README.md` operator notes — `--token` has no default, denylist, `--lab`, PSK required at startup unless REALITY. Do not document `change-me` as a usable default.

5. **`start.sh` / compose**: `start.sh` already mints `BIBA_TOKEN` / `BIBA_PSK`. Do not break that path. No `--lab` required for compose when env secrets are set. `docker-compose.yml` already passes `--token` / `--psk` from env.

## Out of scope

- PSK value denylist (`ComposePSK_ChangeMe`, short PSKs).
- Changing `docker-compose.yml` / `docker-compose.hub.yml` client hardcoded `docker-compose-biba` (not the stock `change-me` default).
- JSON `"lab": true`, JNI/FFI/Tauri UI changes beyond what fall out of `start_json_config`.
- Rotating tokens on existing deployments; mint_invite; PROTOCOL.md; `biba` crate.
- New e2e / Docker / binary-spawn harnesses.
- Wire-format, AUTH, or REALITY handshake changes.

## Files to change

- Create `bibavpn/src/startup_secrets.rs` — denylist, `resolve_cli_token`, `require_psk` (names may vary; keep them `pub` for bins + JSON).
- `bibavpn/src/lib.rs` — `mod` / `pub use` the new helpers.
- `bibavpn/src/bin/server.rs` — drop token default; add `--lab`; call checks before listen.
- `bibavpn/src/bin/client.rs` — same for `--token` / `--psk` after invite merge.
- `bibavpn/src/start_json_config.rs` — fail closed; drop `change-me` fallback and its doc comment.
- `AGENTS.md`, `README.md` — CLI / lab notes only.

## Tests

Run:

```bash
cargo test -p bibavpn
```

Add unit tests next to the new helpers and in `start_json_config.rs` `merge_tests`:

- Denylist: `change-me`, `CHANGE-ME`, `changeme`, ` test `, empty → denied; `t`, `tok`, `test-token`, `docker-compose-biba` → allowed.
- CLI helper: missing token without lab → err; missing token with lab → `change-me`; `change-me` without lab → err; `change-me` with lab → ok.
- PSK helper: missing PSK, no REALITY, no lab → err; REALITY fully configured or lab → ok.
- JSON: no `token` and no `from_invite` → err; `"token":"change-me"` → err; invite without JSON `token` and a non-denylist invite token → ok (extend the existing invite test if needed); token without PSK and without REALITY fields → err.

Do not add `assert_cmd` / `trycmd` unless already in the crate. Existing tests that use `token: "t"` / `"tok"` / `"test-token"` must keep passing. `biba` is not touched — do not add `-p biba`.

## Acceptance criteria

- `bibavpn-server` with no `--token`, or with `--token change-me` (any denylist spelling), exits non-zero unless `--lab` is set.
- `bibavpn-server --lab` with no `--token` starts far enough to accept the lab default (validation of token succeeds); without `--lab` it does not.
- JSON start without `token` and without a valid invite fails; it never substitutes `change-me`.
- JSON start with a denylisted token fails even if `server` is set.
- Server without `--psk` exits non-zero unless `--lab` or REALITY is fully configured.
- `start.sh` still mints a real token/PSK and compose still passes them; that one-command path does not need `--lab`.
- `cargo test -p bibavpn` passes.
- No secrets in logs; `bibavpn_security` WARN when `--lab` is on.

## Non-goals

- Making `--lab` the Docker Hub compose default or minting secrets inside `docker-compose.hub.yml`.
- Blocking weak-but-unique tokens (`t`, `benchtest`) or rewriting smoke scripts to pass `--lab`.
- Failing closed on PSK quality, invite passphrase strength, or `--insecure`.
- Changing how REALITY AUTH uses the token on the wire.
- A config-file / env-var denylist that operators can extend.
