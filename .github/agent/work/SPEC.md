# Spec

## Summary

`--reality-server-names` is parsed, logged, and stored on `RealityServerConfig`, whose docstring calls it the allowlist of accepted TLS SNI / Host values, but `server_handshake_reality` never reads it. Operators can believe REALITY is pinned to a front-domain list while any peer that finishes TLS+WSS and REALITY+token AUTH still gets a mux.

This PR **enforces** the existing allowlist (do not delete the flag). Check presented outer TLS SNI and HTTP `Host` at the start of the REALITY handshake, fail closed when the list is non-empty, and add a handshake test that a non-listed name is rejected before mux. No wire-format change.

## In scope

- Enforce `RealityServerConfig.server_names` inside `server_handshake_reality` (same phase as short-ID checks; before SERVER_HELLO / AUTH work is required, and **before mux**).
- Thread the session’s presented names into that function:
  - **TLS SNI** from the rustls server connection after `TlsAcceptor::accept` (`tokio_rustls::TlsStream::get_ref().1.server_name()`), captured in `handle_one` before the stream is moved into the WebSocket upgrade.
  - **HTTP `Host`** from the upgrade request in `accept_websocket_or_camouflage` (already parsed; currently discarded). Return it alongside `(WebSocketStream, WsHandshakeKind)` so `handle_one` and `reality_handshake` tests can pass it through.
- Matching rules (hostname only, fail closed):
  - Normalize: trim; strip a trailing `:port` (decimal port suffix); compare with `eq_ignore_ascii_case`.
  - Non-empty `server_names`: **every presented identifier that exists** (SNI and/or Host) must be in the list. If **neither** SNI nor Host is present, reject.
  - Empty `server_names` (after parse): accept any name, same idea as empty `--reality-short-ids`. Log a `bibavpn_security` **WARN** at startup. Do not refuse to start.
- Keep today’s default when the flag is **omitted**: `vec![extract_sni(target)]` (host from `--reality-target`). That default is a non-empty list, so production REALITY stays fail-closed to the front host.
- Parse `--reality-server-names` as comma-separated; `trim` each token; **drop empty tokens**. Update clap help so it says the list is enforced.
- On reject, `bail!` with a short reason (no secrets). Existing `handle_one` REALITY `Err` path already records auth failure and logs `bibavpn_security` — reuse it (same as a bad short ID).
- Document empty vs omitted behaviour in `PROTOCOL.md` (REALITY server CLI) and the existing `AGENTS.md` REALITY bullet. One-line README mention only if that REALITY paragraph already lists server flags.

## Out of scope

- Deleting `--reality-server-names` / `server_names`.
- Changing REALITY HELLO / SERVER_HELLO / AUTH bytes (`REALITY_VERSION` stays 2).
- Wildcard / suffix names (`*.vk.com`), IDN/punycode mapping, IPv6 bracket Host parsing beyond “strip `:port` on hostname-shaped values”.
- Enforcing names on non-REALITY (v3 PSK) sessions or on camouflage HTTP.
- Client CLI / invite schema changes (`reality_target` already drives client SNI).
- BoringSSL-specific SNI extraction (server TLS accept is rustls).
- New metrics, new log targets, or new test harnesses.

## Files to change

- `bibavpn/src/reality.rs` — add `is_server_name_allowed` (or equivalent) that **reads** `cfg.server_names`; call it from `server_handshake_reality` with presented SNI/Host; unit tests next to `is_short_id_allowed`.
- `bibavpn/src/bin/server.rs` — capture TLS SNI after accept; pass SNI + Host into `server_handshake_reality`; filter empty name tokens; startup WARN when the parsed list is empty; clap help.
- `bibavpn/src/incoming.rs` — return HTTP `Host` on the WebSocket upgrade path; update in-module callers/tests that destructure the tuple.
- `bibavpn/src/lib.rs` — export the helper only if integration tests need it by name (handshake tests can go through `server_handshake_reality`).
- `bibavpn/tests/reality_handshake.rs` — pass presented names into `server_handshake_reality`; make existing happy-path configs use a list that matches the test client (`127.0.0.1` SNI/Host today); add a test that a non-listed name is rejected. Update the MITM spawn that only calls `accept_websocket_or_camouflage` so it still compiles.
- `PROTOCOL.md` — REALITY server CLI: `--reality-server-names`, omitted = host from target, empty = any + WARN, mismatch dropped before mux.
- `AGENTS.md` — same empty-vs-default sentence on the existing `--reality-server-names` bullet.
- `README.md` — only if the REALITY flag list there would otherwise still imply an unused knob.

## Tests

Do not add a new harness.

- Unit (in `reality.rs`): empty allowlist accepts; listed name matches case-insensitively and with `:443`; mismatch rejects; `None`/`""` presented with a non-empty list rejects.
- Integration (`bibavpn/tests/reality_handshake.rs`): existing accept / wrong-token / missing-AUTH tests still pass with a list that matches the client’s SNI/Host; **new** test: `server_names = ["vk.com"]` (or similar), client still uses `127.0.0.1`, `server_handshake_reality` returns `Err` (dropped before mux). Keep using `spawn_reality_server` / the same TLS+WSS helper — no mux, no compose.

Commands:

```bash
cargo test -p bibavpn
cargo test -p bibavpn --test reality_handshake
```

## Acceptance criteria

- With `--reality-server-names vk.com` (or `RealityServerConfig.server_names = ["vk.com"]`), a session whose TLS SNI and/or HTTP Host is not in that list is rejected in `server_handshake_reality` and never reaches mux.
- A session whose presented SNI/Host **is** in the list still completes REALITY AUTH as today.
- Flag omitted: list defaults to the host from `--reality-target` and is enforced.
- Flag present but parsing yields an empty list: server starts, accepts any name, logs `bibavpn_security` WARN (documented in `PROTOCOL.md` / `AGENTS.md`).
- `server_names` is read on the handshake path; it is not write-only in `bibavpn/src`.
- `cargo test -p bibavpn` passes, including `--test reality_handshake`.

## Non-goals

- Xray-style TLS ClientHello stealing or uTLS REALITY.
- Using this allowlist as a substitute for `--token` / client AUTH MAC.
- Changing camouflage, short-ID semantics, or `--max-concurrent-sessions`.
- Client-side validation of `server_names` (client already sets SNI from `reality_target`).
