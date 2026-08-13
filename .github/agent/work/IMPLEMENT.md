# Implementation notes

All spec tests ran successfully in this environment.

## Review fix

`ProfilesScreen` receives full `SavedConfig` from `get_edit_config` (no `has_*` flags). Subtitle now derives invite presence from `String(p.from_invite || "").trim()` instead of `p.has_from_invite`. Connect / poll snapshot still uses `has_invite` / `has_from_invite` on `PublicTunnelProfile`.

## Tests

- `cargo test -p bibavpn-desktop --locked` — 24 passed
- `npm run build --prefix apps/bibavpn-desktop/ui` — ok
