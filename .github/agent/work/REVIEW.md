VERDICT: PASS

- Shared `startup_secrets` helpers cover the spec denylist (trim + case-insensitive `change-me` / `changeme` / `test`, empty/whitespace denied; `t` / `tok` / `test-token` / `testtok` / `wsl-test-token` / `docker-compose-biba` allowed), CLI `resolve_cli_token` lab hatch, and `require_psk` unless lab or fully configured REALITY.
- Both binaries dropped clap’s `--token` default, added `--lab` (WARN on `bibavpn_security`, no token/PSK in logs), and run checks before listen / after invite merge. JSON start no longer falls back to `change-me`; there is no JSON `lab` bypass.
- Named unit tests are present next to the helpers and in `start_json_config` `merge_tests`. `TEST.log` shows `cargo test -p bibavpn` green, including those cases.
- Diff stays in the spec file list (`startup_secrets.rs`, `lib.rs`, bins, `start_json_config.rs`, `AGENTS.md`, `README.md`). `start.sh` / compose untouched; deferred v3 PSK path unchanged; no secrets added.
