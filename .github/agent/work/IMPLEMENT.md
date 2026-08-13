# Implementation

Removed the public default tunnel token (`change-me`) and added startup secret validation.

## Changes

- **`bibavpn/src/startup_secrets.rs`** — shared denylist, `resolve_cli_token`, `validate_resolved_token`, `require_psk`, REALITY helpers, lab/reality WARN loggers.
- **`bibavpn/src/bin/server.rs`** — `--token` optional only with `--lab`; startup checks before listen.
- **`bibavpn/src/bin/client.rs`** — same token/PSK rules after invite merge.
- **`bibavpn/src/start_json_config.rs`** — fail closed (no `change-me` fallback); JSON tests extended.
- **`AGENTS.md`**, **`README.md`** — operator notes for denylist, `--lab`, PSK at startup.

## Tests

```bash
cargo test -p bibavpn
```

All tests passed in CI environment (2026-08-13).
