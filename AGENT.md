# BibaVPN — context for agents and developers

This document describes architecture, design choices, and workflows for the repository. The goal is to keep contributions consistent and deployments safe.

## What the project is

**BibaVPN** is a proxy stack: local **SOCKS5** and optional **HTTP CONNECT** → **TLS + WebSocket** → remote entry server → outbound TCP to the Internet. Optionally **BibaV2** (PSK, AEAD, decoy) and **BibaV2.1** (WS ping, frame size cap, custom headers, early noise) sit on top of the transport.

Typical traffic path:

1. The application (browser, messenger, etc.) connects to **SOCKS5** on loopback (or `0.0.0.0` in a container).
2. The client does **not** encrypt the local SOCKS hop — it is plain SOCKS5.
3. The client opens **WSS**, optionally **BibaV2**: HELLO/ACK, keys from PSK, **ChaCha20-Poly1305** on frames, random decoy bytes in plaintext before AEAD.
4. The server terminates TLS/WebSocket and outer crypto, then forwards to target host:port using the inner protocol (OPEN + padded frames).

## Layout


| Path                                                               | Role                                                                    |
| ------------------------------------------------------------------ | ----------------------------------------------------------------------- |
| `bibavpn/`                                                         | Crate: `lib` plus `bibavpn-server`, `bibavpn-client` binaries           |
| `bibavpn/src/crypto_layer.rs`                                      | BibaV2: BLAKE3 derive, HELLO/ACK, MAC, `SessionCrypto`, decoy           |
| `bibavpn/src/bin/server.rs`                                        | Server entry (TLS, WSS, token, PSK)                                     |
| `bibavpn/src/bin/client.rs`                                        | Client entry (SOCKS5, HTTP CONNECT, WSS, PSK)                           |
| `bibavpn/src/socks5.rs`                                            | SOCKS5 frontend                                                         |
| `bibavpn/src/tls_util.rs`, `frame.rs`, `protocol.rs`, `stealth.rs` | TLS, framing, OPEN, WS upgrade (incl. BibaV2.1 header knobs)            |
| `bibavpn/src/ws_bridge.rs`                                         | Shared WS↔TCP bridge: BibaV2 seal/open, MTU cap, ping/pong              |
| `bibavpn/src/http_connect.rs`                                      | HTTP `CONNECT` on a separate listen port                                |
| `docker/`                                                          | `Dockerfile.server`, `Dockerfile.client` (multi-stage, Rust **≥ 1.89**) |
| `docker-compose.yml`                                               | Local lab: server + client on one Docker network                        |
| `docker-compose.remote-client.yml`                                 | Client only toward remote `host:8443`, proxies on the host              |
| `scripts/`                                                         | Smoke tests, deploy helpers, benchmarks                                 |


## BibaV2 (short)

- Enabled with matching `**--psk`** and `**--decoy-max`** on client and server.
- HELLO: magic `BIBV2HL1` + 32-byte client random.
- ACK: `BIBV2ACK1` + server random + 16-byte keyed MAC (BLAKE3 over PSK).
- Directional keys: separate `derive` `**bibavpn.v2.c2s`** / `**bibavpn.v2.s2c**` (split directions like many v2ray-style designs).
- On the wire: 12-byte nonce + ciphertext; plaintext is optional decoy `0..N` bytes then payload.
- Unit tests live in `crypto_layer` and `frame`; wire-format changes need matching client/server updates and tests.

## BibaV2.1 (WebSocket behaviour and fingerprint)

Compatible with the **same** BibaV2 PSK/decoy when both ends use the same new flags.

- `**--ws-ping-secs`**: periodic WebSocket **Ping** during tunneling (`0` = off). Incoming **Ping** gets **Pong** (including while waiting for HELLO/OPEN). Reduces idle/NAT drops.
- `**--max-ws-binary`**: max size of one **outgoing** WS binary (and coarse inbound check). TCP is read in chunks; with BibaV2 account for nonce/tag/decoy (see `frame::max_tcp_payload_per_ws_message`). Default **1400** (MTU-oriented).
- `**--ws-host`**, `**--ws-origin`**, `**--ws-user-agent**`, `**--ws-accept-language**`, repeatable `**--ws-header 'Name: value'**` customize the HTTP upgrade instead of a fixed header set.
- `**--early-ws-frames**`: count of random binary frames **right after** the WS upgrade (before junk/HELLO) to vary startup pattern.

`**rust-toolchain.toml` pins 1.89.0**: on **rustc 1.93** building `bibavpn-server` hit an ICE in early lint; pinning 1.89 stabilizes `cargo build`. Docker images use Rust 1.89+.

## Build and run (local)

```bash
cargo build --release -p bibavpn --bin bibavpn-server
cargo build --release -p bibavpn --bin bibavpn-client
```

Example client to a remote server (lab TLS — only if you trust the path):

```bash
./target/release/bibavpn-client \
  --server VPS:8443 --sni VPS_IP_OR_HOST \
  --token YOUR_TOKEN --insecure \
  --socks5 127.0.0.1:1080 \
  --psk YOUR_PSK --decoy-max 32 --max-pad 64 \
  --max-ws-binary 1400 --ws-ping-secs 25
```

Server (demo self-signed):

```bash
./target/release/bibavpn-server \
  --listen 0.0.0.0:8443 \
  --self-signed-san YOUR_SAN \
  --token YOUR_TOKEN \
  --psk YOUR_PSK --decoy-max 32 --max-pad 64 \
  --max-ws-binary 1400 --ws-ping-secs 25
```

**Note:** `--insecure` on the client and self-signed on the server are for **tests only**. Production should use real certificates (e.g. Let’s Encrypt behind a reverse proxy) and **no** `--insecure`.

## Docker / Compose gotcha

`Dockerfile.`* sets `**ENTRYPOINT`** to the binary path. In `docker-compose.yml`, `**command`** must list **argument flags only** (do not repeat the binary path). Otherwise `clap` sees an extra token and the container exits with code 2.

Images use `**rust:1.89-bookworm`** (or newer): older `cargo` cannot build dependencies that use edition 2024.

## Scripts


| Script                             | Purpose                                                                                                       |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `scripts/docker-smoke.sh`          | `docker compose up`, `curl` via SOCKS `127.0.0.1:11080` and HTTP proxy, `down`                                |
| `scripts/wsl-test.sh`              | Local smoke (plain/PSK) on WSL                                                                                |
| `scripts/remote-install-server.sh` | Build server image, `docker save`                                                                             |
| `scripts/speedtest-via-socks.py`   | Speedtest via SOCKS (`pysocks`, `speedtest-cli`)                                                              |
| `scripts/run-remote-speedtest.sh`  | SSH to VPS, venv, `speedtest-cli --simple` on the server (reads password/port from `server.txt` — gitignored) |


Remote client with Docker:

```bash
cd biba-vpn   # directory containing this compose file
export BIBA_REMOTE=vps:8443 BIBA_SNI=... BIBA_VPN_TOKEN=... BIBA_VPN_PSK=...
docker compose -f docker-compose.remote-client.yml up -d --build
```

Default SOCKS on host: `**127.0.0.1:11090**` (override with `BIBA_SOCKS_HOST_PORT` / `BIBA_SOCKS_CONTAINER_PORT`). HTTP CONNECT defaults to `**11880**` on the host.

## Security

- **Do not commit:** `server.txt`, `.env`, `.env.remote`, passwords, PEM keys (see `.gitignore`).
- Treat PSK and token as **secrets**; rotate and restart both ends on leak.
- Prefer **SSH keys** over long-term `sshpass`.
- Do not embed real credentials in docs or examples.

## Guidelines for agents

1. Touch only what the task needs; avoid unrelated refactors.
2. Match existing style (`clap`, `tracing`, async, imports).
3. Any BibaV2 wire change: update client **and** server plus tests.
4. After Docker/Compose edits, run `scripts/docker-smoke.sh`.
5. Use env vars and placeholders — never real IPs/passwords/PSK in the tree.

## Scenarios that were validated

- Local compose: SOCKS → `example.com`.
- Workstation client → remote server → HTTPS (including `api.telegram.org`).
- Speedtest via SOCKS (`speedtest-via-socks.py` in a venv).
- Server/client images build with the Rust version pinned in the Dockerfiles.

---

*For humans and AI agents working on the BibaVPN repository.*