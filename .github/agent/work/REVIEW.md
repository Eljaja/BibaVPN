VERDICT: PASS

- `StateSnapshot.cfg` is `PublicSavedConfig` / `PublicTunnelProfile`; secret keys (`token`, `psk`, `from_invite`, `invite_passphrase`, `pin_cert_pem`) are omitted from the poll DTO and replaced with the specified `has_*` flags (trim + non-empty; `has_invite` is the AND of invite URI + passphrase).
- `get_edit_config` is registered next to `get_state`. Settings/Profiles load and refresh that full `SavedConfig`; `save_config_cmd` / `apply_invite` do not copy `snap.cfg` into the draft.
- `save_config_cmd` merges secrets by profile `id`: omitted keys keep stored values, present `""` clears, new ids stay empty, deleted profiles are dropped.
- Connect uses `has_invite` from the poll snapshot. Profiles (edit `SavedConfig`) derives the subtitle from `from_invite`, so invite-only rows still show `display_invite`.
- `server_card_subtitle` / `display_host_line` use the non-secret «Ключ Biba» label; named unit tests in `config.rs` cover omit-keys, `has_*`, subtitle, and merge. No extra crates, no on-disk schema change, no real secrets added.
