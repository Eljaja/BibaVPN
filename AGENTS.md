# BibaVPN — context for agents and developers

This document describes architecture, design choices, and workflows for the repository. The goal is to keep contributions consistent and deployments safe.

## What the project is

**BibaVPN** is a proxy stack: local **SOCKS5** (TCP **CONNECT** and **UDP ASSOCIATE**) and optional **HTTP CONNECT** → **TLS + WebSocket** → remote entry server → outbound **TCP or UDP** to the Internet. Optionally **BibaV2** (PSK, AEAD, decoy) and **BibaV2.1** (WS ping, frame size cap, custom headers, early noise) sit on top of the transport.

**TCP — default:** many SOCKS connections share **one** TLS+WSS session (**TCP mux** in `tcp_mux.rs`): after **AUTH** and optional BibaV2 preamble, the client sends **`MUX_OPEN`**; per-target opens use mux records (stream id, flags, payload) inside padded frames, with window-based flow control. Use **`--no-mux`** for legacy **one WSS per SOCKS CONNECT** (`OPEN` + binary loop).

**UDP** (e.g. DNS via SOCKS5 UDP) uses a **separate** shared WSS: **`UDP_MUX_OPEN`** (`protocol.rs`), then **UDP_REQ** / **UDP_REP** (`udp_mux.rs`). Same TLS/WebSocket fingerprint class as TCP from the client to the VPS.

**HTTP on the TLS port:** non-WebSocket requests are served as **camouflage** (`incoming.rs`, `camouflage.rs`): nginx-style responses, optional **`--camouflage-dir`** static files, or **`--camouflage-url`** (`http://host:port` only — plaintext to origin).

**DPI-oriented options:** `--pad-mode random|http-buckets`, `--dummy-interval-secs` (idle empty padded frames on the tunnel; mux shares one outer connection), client-only decoy **`--decoy-gets`** (+ interval and comma-separated paths), **`stealth.rs`** WebSocket upgrade header order per TLS profile (Chrome / Firefox).

Typical traffic path (TCP, mux):

1. Application → **SOCKS5** (plain local hop).
2. Client opens **WSS** to configured **`--ws-path`** (default `/ws`); **token** in **AUTH** binary (`protocol.rs`, `ws_auth.rs`), not in the URL.
3. Optional **BibaV2** HELLO/ACK and AEAD on frames.
4. **MUX_OPEN** then stream **OPEN** / **DATA** / close; server dispatches to per-stream TCP (`bridge_ws_tcp_mux_server`).

Typical path (UDP via SOCKS): same as before — **UDP ASSOCIATE** → shared **UdpMuxHandle** and dedicated WSS.

## Layout

| Path | Role |
| ---- | ---- |
| `bibavpn/` | Crate: `lib` plus `bibavpn-server`, `bibavpn-client` binaries |
| `bibavpn/src/crypto_layer.rs` | BibaV2: BLAKE3 derive, HELLO/ACK, MAC, `SessionCrypto`, decoy |
| `bibavpn/src/bin/server.rs` | TLS accept; **first-byte HTTP vs WS** via `incoming`; AUTH; `wait_first_channel` → TCP bridge, **TCP mux**, or UDP mux |
| `bibavpn/src/bin/client.rs` | Client CLI; invite merge for `ws_path`, `pad_mode`, `dummy_interval_secs`, decoy flags |
| `bibavpn/src/incoming.rs` | Read HTTP request on TLS; WebSocket **101** + `WebSocketStream::from_partially_read`; or serve camouflage GET/HEAD |
| `bibavpn/src/camouflage.rs` | Shared HTML / 404 bodies for rejects and static fallbacks |
| `bibavpn/src/ws_auth.rs` | Server waits for **AUTH** frame (timeout, skip noise) |
| `bibavpn/src/tcp_mux.rs` | Mux wire format, client handle, server bridge, optional idle dummy on mux |
| `bibavpn/src/decoy_traffic.rs` | Optional parallel short **HTTPS GETs** (same TLS profile as tunnel) |
| `bibavpn/src/socks5.rs` | SOCKS5 frontend (CONNECT + **UDP ASSOCIATE** replies) |
| `bibavpn/src/local_client.rs` | SOCKS dispatch, mux slot, UDP mux, decoy spawn, `LocalClientOptions` |
| `bibavpn/src/udp_mux.rs` | Client driver + **`bridge_ws_udp_mux_server`**; padded frames + optional `pad_mode` |
| `bibavpn/src/protocol.rs` | OPEN, **AUTH**, **UDP_MUX_OPEN**, UDP_REQ/REP, ATYP helpers |
| `bibavpn/src/tls_util.rs`, `frame.rs`, `stealth.rs` | TLS profiles, **PadMode**, WS upgrade (ordered headers, UA / Sec-CH) |
| `bibavpn/src/ws_bridge.rs` | WebSocket to TCP bridge (legacy per-connection TCP); ping + **dummy** task; `pad_mode` |
| `bibavpn/src/http_connect.rs` | HTTP `CONNECT` on a separate listen port |
| `bibavpn/src/invite_uri.rs` | **`InviteV1`**: optional `ws_path`, `pad_mode`, `dummy_interval_secs` |
| `bibavpn/src/lib.rs` | Module exports |
| `docker/` | `Dockerfile.server`, `Dockerfile.server.binary`, `Dockerfile.client` |
| `docker-compose.yml` | Local lab: server + client on one Docker network |
| `scripts/` | Smoke tests, deploy helpers, benchmarks |

## BibaV2 (short)

- Enabled with matching `--psk` and `--decoy-max` on client and server.
- HELLO: magic `BIBV2HL1` + 32-byte client random.
- ACK: `BIBV2ACK1` + server random + 16-byte keyed MAC (BLAKE3 over PSK).
- Directional keys: `bibavpn.v2.c2s` / `bibavpn.v2.s2c`.
- On the wire: 12-byte nonce + ciphertext; plaintext is optional decoy `0..N` bytes then **inner payload** (padded frame or mux record, etc.).
- Unit tests in `crypto_layer`, `frame`, `protocol` (AUTH); wire-format changes need client **and** server updates.

## BibaV2.1 and transport knobs

Compatible with the same BibaV2 PSK/decoy when both ends match.

- `--ws-ping-secs`, `--ws-ping-jitter-percent`, `--ws-binary-send-jitter-ms`
- `--max-ws-binary` — cap outgoing WS binary (see `frame::max_tcp_payload_per_ws_message`; mux code reserves **9 bytes** for the mux record header when chunking TCP).
- `--udp-max-pad`, `--udp-max-ws-binary`, `--udp-mux-reply-timeout-secs` (client), `--udp-mux-recv-timeout-secs` (server)
- `--ws-host`, `--ws-origin`, `--ws-user-agent`, `--ws-accept-language`, `--ws-header`
- `--early-ws-frames`, `--junk-frames`
- `--pin-cert` (client) — incompatible with `--insecure`
- `--ws-path` / server `--ws-path` — WebSocket path; token via **AUTH** (default `/ws`)
- Server `--legacy-path-auth` — accept old `/b/{token}` without AUTH (less safe)
- `--pad-mode random|http-buckets` — padding distribution (invite may carry `pad_mode` string)
- `--dummy-interval-secs` — idle empty padded frames (`0` = off); invite may set `dummy_interval_secs`
- Client `--decoy-gets`, `--decoy-gets-interval-secs`, `--decoy-gets-paths` — not part of invite JSON (client-only)
- Server `--camouflage-dir`, `--camouflage-url` (`http://` upstream only)

`rust-toolchain.toml` pins a stable Rust version for reproducible builds. Docker images use a matching or newer toolchain.

Wire layouts (padded frame, BibaV2, AUTH, OPEN, mux, UDP mux) are in **[README.md](README.md)**.

## Build and run (local)

```bash
cargo build --release -p bibavpn --bin bibavpn-server
cargo build --release -p bibavpn --bin bibavpn-client
```

Example client (lab TLS — only if you trust the path):

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

**Note:** `--insecure` and self-signed are for **tests only**. Production: real certificates (e.g. Let’s Encrypt behind a reverse proxy) and no `--insecure`.

## Docker / Compose gotcha

`Dockerfile.*` sets **ENTRYPOINT** to the binary path. In `docker-compose.yml`, **`command`** must list **argument flags only** (do not repeat the binary path). Otherwise `clap` sees an extra token and the container exits with code 2.

**Small VPS / low disk:** use local build (e.g. WSL) + **`docker/Dockerfile.server.binary`** — see **`scripts/remote-deploy.sh`**.

## Scripts

| Script | Purpose |
| ------ | ------- |
| `scripts/docker-smoke.sh` | `docker compose up`, `curl` via SOCKS and HTTP proxy, `down` |
| `scripts/udp-socks-smoke.sh` | TCP via SOCKS + **UDP DNS** over SOCKS |
| `scripts/wsl-test.sh` | Local smoke (plain/PSK) on WSL |
| `scripts/wsl-local-bench.sh` | **64 MiB** HTTP direct vs SOCKS+WSS throughput (run in WSL from repo root) |
| `scripts/remote-deploy.sh` | Sync + build + `Dockerfile.server.binary` deploy |
| `scripts/remote-install-server.sh` | Build server image, `docker save` |
| `scripts/speedtest-via-socks.py` | Speedtest via SOCKS |
| `scripts/run-remote-speedtest.sh` | SSH + `speedtest-cli` on VPS |

**Remote client in Docker:** build `docker/Dockerfile.client`, `docker run` with published SOCKS/HTTP proxy ports; use `0.0.0.0` binds inside the container.

## UDP design note (agents)

The server keeps a **pending map** (by destination `SocketAddr`) to correlate **UDP_REP** to **UDP_REQ**. Under many concurrent requests to the same `IP:port`, ordering assumptions matter (xid is per datagram).

## Security

- **Do not commit:** `server.txt`, `.env`, passwords, PEM keys (see `.gitignore`).
- Treat PSK, token, and invite passphrase as **secrets**.
- `--pin-cert` narrows trust; do not combine with `--insecure` on the client.
- Prefer **SSH keys** for `remote-deploy.sh`.
- Do not embed real credentials in docs or examples.

## Guidelines for agents

1. Touch only what the task needs; avoid unrelated refactors.
2. Match existing style (`clap`, `tracing`, async, imports).
3. Any wire-format change: update client **and** server plus tests; keep **[README.md](README.md)** in sync for on-wire layouts.
4. After Docker/Compose edits, run `scripts/docker-smoke.sh`; after UDP changes, `scripts/udp-socks-smoke.sh`; for throughput sanity, `scripts/wsl-local-bench.sh` (WSL).
5. Use placeholders — never real IPs/passwords/PSK in the tree.

## Scenarios that were validated

- Local compose: SOCKS → example hosts.
- Workstation client → remote server → HTTPS.
- **SOCKS UDP** (DNS) via UDP mux (`udp-socks-smoke.sh`).
- **WSL local bench**: direct HTTP vs SOCKS+WSS 64 MiB (`wsl-local-bench.sh`).
- Speedtest via SOCKS (`speedtest-via-socks.py` in a venv).
- Server/client images and slim remote image via `Dockerfile.server.binary`.

---

*For humans and AI agents working on the BibaVPN repository.*

