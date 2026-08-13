# Spec

## Summary

`get_state` and the `vpn-state` event currently serialize the full in-memory `SavedConfig` (including `token`, `psk`, `from_invite`, `invite_passphrase`, and `pin_cert_pem`) into the WebView on every poll. Change `StateSnapshot` to a public view of config (host, split-tunnel flags, `can_connect`, presence booleans) so tunnel secrets stay in the Rust process and on disk. Settings still edits secrets via a dedicated, non-polled command. `save_config_cmd` must not wipe stored secrets if the UI accidentally posts a redacted payload.

## In scope

- Replace `StateSnapshot.cfg: SavedConfig` with a public DTO (`PublicSavedConfig` / `PublicTunnelProfile`) built in `snapshot()`. Omit these profile fields from that JSON (keys must not appear, not empty strings):
  - `token`
  - `psk`
  - `from_invite`
  - `invite_passphrase`
  - `pin_cert_pem`
- Per profile on the public view, add booleans derived from the stored profile (trim, then non-empty):
  - `has_token`
  - `has_psk`
  - `has_from_invite`
  - `has_invite_passphrase`
  - `has_invite` (`has_from_invite && has_invite_passphrase`)
  - `has_pin_cert`
- Keep all other profile/root fields that the Connect / Profiles / Settings UIs already read from `snap.cfg` (server, SNI, split-tunnel, locale, ports, stealth knobs, etc.). `Inner.cfg` and `config.json` stay `SavedConfig` and keep storing secrets.
- Stop putting invite URI material in `server_card_subtitle` (today it prefixes `from_invite`). Use the same non-secret invite label as `display_host_line` (`"Ключ Biba"` / existing i18n `display_invite` on the UI side). `displayHost` / `serverSubtitle` on the snapshot must not contain `biba://` or passphrase text.
- Add `get_edit_config` (Tauri command, not used by the poll path) that returns the full `SavedConfig` for the Settings and Profiles tabs so those forms can still show and save secret fields.
- Load that edit config when entering Settings or Profiles; never use a poll snapshot as the `save_config_cmd` payload. After `save_config_cmd` / `apply_invite_cmd` while those tabs are open, refresh via `get_edit_config` (do not copy `snap.cfg` into the settings draft).
- `save_config_cmd`: merge secrets by profile `id`. If an incoming profile JSON **omits** a secret key, keep the stored value. If the key is **present** (including `""`), honor it so the user can clear a field from Settings. New profiles have empty secrets. Deleted profiles are dropped.
- Connect UI: `inviteMode` / profile list subtitle must use `has_invite` / `has_from_invite`, not `from_invite` / `invite_passphrase` from the poll snapshot.
- Register `get_edit_config` in the invoke handler next to `get_state`.

## Out of scope

- Encrypting `config.json` at rest, OS keychain, or changing the on-disk schema.
- Making Settings write-only (never showing stored token/PSK/invite in the WebView even while the tab is open).
- Redacting additional profile fields (`reality_public_key`, `reality_short_id`, `ws_headers`, control-plane URLs).
- WebView XSS hardening, CSP, or IPC log redaction beyond this snapshot.
- Standalone Compose Android app under `apps/android/`.
- Wire-format / `bibavpn` crate / `biba` crate changes.

## Files to change

- `apps/bibavpn-desktop/src-tauri/src/config.rs` — public DTO + `SavedConfig` → public mapping; `server_card_subtitle` without invite URI; secret-merge helper; unit tests.
- `apps/bibavpn-desktop/src-tauri/src/lib.rs` — `StateSnapshot.cfg` type; `snapshot()` mapping; `get_edit_config`; `save_config_cmd` merge; invoke handler.
- `apps/bibavpn-desktop/ui/src/vpnTypes.ts` — `PublicTunnelProfile` / `PublicSavedConfig` vs edit `SavedConfig`; `StateSnapshot.cfg` is public.
- `apps/bibavpn-desktop/ui/src/useVpn.jsx` — `getEditConfig` invoke; poll/listen path unchanged except types.
- `apps/bibavpn-desktop/ui/src/App.jsx` — load edit config on Settings/Profiles; do not save `snap.cfg` from `get_state`.
- `apps/bibavpn-desktop/ui/src/screens/ConnectScreen.jsx` — `has_invite` for invite mode.
- `apps/bibavpn-desktop/ui/src/screens/ProfilesScreen.jsx` — `has_from_invite` instead of reading `from_invite`.

`SettingsScreen.jsx` / `profileUtils.js` keep editing `SavedConfig` from `get_edit_config`; only types/comments if required.

## Tests

Add unit tests next to the mapping/merge helpers in `apps/bibavpn-desktop/src-tauri/src/config.rs` (same `#[cfg(test)]` style as `split_bypass_json_tests`):

- Serialize a `SavedConfig` with non-empty `token`, `psk`, `from_invite` (`biba://…`), `invite_passphrase`, and `pin_cert_pem` through the public snapshot DTO (or `serde_json::to_value` of `StateSnapshot`-shaped cfg). Assert the JSON text/`Value` does **not** contain those keys and does **not** contain the secret substrings.
- Assert the corresponding `has_*` booleans are true; empty fields → false.
- `server_card_subtitle` for an invite-only profile does not contain `biba://` or the URI body.
- Merge: omitted secret keys preserve stored values; present empty strings clear them; new profile id does not copy another profile’s secrets.

Run:

```bash
cargo test -p bibavpn-desktop --locked
```

UI has no unit test runner; after JSX/type changes, sanity-compile the frontend with the existing script:

```bash
npm run build --prefix apps/bibavpn-desktop/ui
```

Do not add a new test harness. Do not run `cargo test -p bibavpn` unless this PR accidentally touches that crate (it should not).

## Acceptance criteria

- `get_state` and `vpn-state` JSON do not contain `token`, `psk`, `invite_passphrase`, `from_invite`, `pin_cert_pem`, or invite URI material (including `serverSubtitle`).
- Poll snapshot still exposes enough public state for Connect: `canConnect`, `displayHost`, split-tunnel flags, `has_invite` / `has_psk` (and the other `has_*` flags above).
- Opening Settings still shows stored invite URI, passphrase, token, PSK, and PEM via `get_edit_config`; applying an invite and saving still persist into `Inner.cfg` / disk and still connect.
- Switching/adding/deleting profiles from the Profiles tab does not blank stored secrets on other profiles.
- Connect still works from `connect_cmd` using in-process `SavedConfig` (no secrets required on the poll snapshot).
- `cargo test -p bibavpn-desktop --locked` passes.

## Non-goals

- Removing secrets from the WebView for the duration of a Settings editing session.
- Changing proto 3, REALITY, or any on-wire layout.
- Rotating or invalidating existing invites/tokens.
- Logging/metrics changes beyond not serializing secrets on the snapshot path.
