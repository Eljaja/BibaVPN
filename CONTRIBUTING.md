# Contributing to BibaVPN

Thanks for taking the time to poke at BibaVPN. This is a small, opinionated
project, so please read this short guide before opening a large patch.

## Ground rules

- **Be nice.** No discussion about whether circumvention tooling should exist
  will be entertained in issues or PRs — that ship has sailed.
- **No real secrets in commits.** `PSK`, tokens, invite passphrases, VPS IPs
  and passwords belong in environment variables, not in code or docs. See
  [SECURITY.md](SECURITY.md).
- **Small, focused PRs** beat large "cleanup + feature" patches. If you want
  to refactor an area, open an issue first.

## Getting the code

```bash
git clone https://github.com/Eljaja/BibaVPN.git biba-vpn
cd biba-vpn
rustup show            # installs the toolchain pinned in rust-toolchain.toml
cargo build --workspace
cargo test --workspace
```

For the Android core:

```bash
./scripts/wsl-build-all.sh          # WSL / Linux
# or
./scripts/build-android-jni.ps1     # Windows PowerShell
```

For the Tauri desktop app:

```bash
cd bibavpn-desktop/ui && npm install
cd .. && cargo tauri dev
```

## Workflow

1. Fork the repo, create a branch off `main` with a descriptive name, e.g.
   `feat/udp-mux-backpressure` or `fix/ws-ping-jitter`.
2. Keep the change **self-contained**: code + tests + docs in the same PR.
3. Run the smoke scripts that cover the area you touched:
   - `scripts/docker-smoke.sh` — compose build + SOCKS / HTTP CONNECT curl
   - `scripts/udp-socks-smoke.sh` — TCP via SOCKS + UDP DNS over SOCKS
   - `scripts/wsl-local-bench.sh` — 64 MiB throughput sanity (WSL)
4. Update **[PROTOCOL.md](PROTOCOL.md)** if you change anything on the wire.
   Wire-format changes must land **client and server in the same PR**.
5. Update **[AGENTS.md](AGENTS.md)** if you add / rename a CLI flag, script
   or module.

## Coding style

- Rust: follow `cargo fmt` and `cargo clippy --workspace -- -D warnings`.
  We match the existing patterns for `clap`, `tracing`, and async (Tokio).
- Kotlin / Android: match the style already in `android/app/src/main/java`.
- Shell scripts: `set -euo pipefail`, prefer `"${VAR:?message}"` over
  implicit empty defaults for required inputs.
- Commit messages: conventional-style prefix is appreciated
  (`feat(bibavpn): …`, `fix(android): …`, `chore(ci): …`) but not enforced.

## What is most useful right now

- Better DPI evasion diagnostics (scripts in `scripts/bibavpn_*_probe.py`).
- Real TLS certificate workflow in Docker (Caddy / Traefik sidecar).
- iOS port (Tauri or native) — the design system is documented in
  [DESIGN.md](DESIGN.md).
- Fuzzing the frame and mux parsers (`frame.rs`, `tcp_mux.rs`).
- More thorough integration tests in `scripts/bibavpn_e2e.py`.

Open an issue tagged `good first issue` if you want to pick something
small, and a `rfc` issue for anything that changes the wire format.
