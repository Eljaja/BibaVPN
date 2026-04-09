# BibaVPN — context for agents and developers

This document describes architecture, design choices, and workflows for the repository. The goal is to keep contributions consistent and deployments safe.

## What the project is

**BibaVPN** is a proxy stack: local **SOCKS5** (TCP **CONNECT** and **UDP ASSOCIATE**) and optional **HTTP CONNECT** → **TLS + WebSocket** → remote entry server → outbound **TCP or UDP** to the Internet. Optionally **BibaV2** (PSK, AEAD, decoy) and **BibaV2.1** (WS ping, frame size cap, custom headers, early noise) sit on top of the transport.

**TCP** from applications uses one WSS session per SOCKS connection (OPEN → binary loop).

**UDP** (e.g. DNS via SOCKS5 UDP) is carried over a **separate** TLS+WSS session: the client opens a **UDP mux** (`UDP_MUX_OPEN` in `protocol.rs`), then **UDP_REQ** / **UDP_REP** frames fan out to a shared `UdpSocket` on the server. On the wire to the censor, UDP payloads are still **inside WebSocket binary frames over TLS**—same class of fingerprint as the TCP tunnel, not “raw UDP” on the client↔VPS leg. After decapsulation on the server, egress to `host:port` is ordinary UDP.

Typical traffic path (TCP):

1. The application connects to **SOCKS5** on loopback (or `0.0.0.0` in a container).
2. The client does **not** encrypt the local SOCKS hop — it is plain SOCKS5.
3. The client opens **WSS**, optionally **BibaV2**: HELLO/ACK, keys from PSK, **ChaCha20-Poly1305** on frames, random decoy bytes in plaintext before AEAD.
4. The server terminates TLS/WebSocket and outer crypto, then forwards to target host:port using the inner protocol (OPEN + padded frames).

Typical path (UDP via SOCKS):

1. SOCKS5 **UDP ASSOCIATE** on the client; replies use SOCKS5 UDP framing (`socks5.rs` helpers + `parse_socks5_udp_datagram` / `build_socks5_udp_datagram` in `protocol.rs`).
2. One **shared** UDP mux handle per process (`local_client.rs`) speaking **UDP_REQ**/**UDP_REP** on the dedicated WSS (`udp_mux.rs`).

## Layout


| Path                                                | Role                                                                                                             |
| --------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `bibavpn/`                                          | Crate: `lib` plus `bibavpn-server`, `bibavpn-client` binaries                                                    |
| `bibavpn/src/crypto_layer.rs`                       | BibaV2: BLAKE3 derive, HELLO/ACK, MAC, `SessionCrypto`, decoy                                                    |
| `bibavpn/src/bin/server.rs`                         | Server entry (TLS, WSS, token, PSK); `wait_first_channel` → TCP bridge or **UDP mux** bridge                     |
| `bibavpn/src/bin/client.rs`                         | Client entry (SOCKS5, HTTP CONNECT, WSS, PSK)                                                                    |
| `bibavpn/src/socks5.rs`                             | SOCKS5 frontend (CONNECT + **UDP ASSOCIATE** replies)                                                            |
| `bibavpn/src/local_client.rs`                       | SOCKS dispatch, **UDP ASSOCIATE**, shared `UdpMuxHandle`                                                         |
| `bibavpn/src/udp_mux.rs`                            | Client driver + server **bridge_ws_udp_mux_server**; `Arc<UdpSocket>`; pending xid routing                       |
| `bibavpn/src/protocol.rs`                           | OPEN, padding, **UDP_MUX_OPEN**, UDP_REQ/REP, SOCKS5 UDP helpers, ATYP helpers                                   |
| `bibavpn/src/tls_util.rs`, `frame.rs`, `stealth.rs` | TLS, framing, WS upgrade (incl. BibaV2.1 header knobs)                                                           |
| `bibavpn/src/ws_bridge.rs`                          | Shared WS↔TCP bridge: BibaV2 seal/open, MTU cap, ping/pong                                                       |
| `bibavpn/src/http_connect.rs`                       | HTTP `CONNECT` on a separate listen port                                                                         |
| `bibavpn/src/lib.rs`                                | Exports `udp_mux` and other modules                                                                              |
| `docker/`                                           | `Dockerfile.server` (in-container Rust build), `Dockerfile.server.binary` (prebuilt binary), `Dockerfile.client` |
| `docker-compose.yml`                                | Local lab: server + client on one Docker network                                                                 |
| `scripts/`                                          | Smoke tests, deploy helpers, benchmarks                                                                          |


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
- `**--early-ws-frames`**: count of random binary frames **right after** the WS upgrade (before junk/HELLO) to vary startup pattern.

`**rust-toolchain.toml` pins 1.89.0**: on **rustc 1.93** building `bibavpn-server` hit an ICE in early lint; pinning **1.89** stabilizes `cargo build`. Docker images use Rust **1.89+**.

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

`Dockerfile.*` sets `**ENTRYPOINT`** to the binary path. In `docker-compose.yml`, `**command`** must list **argument flags only** (do not repeat the binary path). Otherwise `clap` sees an extra token and the container exits with code 2.

Images use `**rust:1.89-bookworm`** (or newer): older `cargo` cannot build dependencies that use edition 2024.

**Small VPS / low disk:** full `Dockerfile.server` pulls the Rust toolchain inside Docker and can exceed available space. Use **local Linux build** (e.g. WSL) + `**docker/Dockerfile.server.binary`** (copy prebuilt `bibavpn-server`) — see `**scripts/remote-deploy.sh**`.

## Scripts


| Script                             | Purpose                                                                                                                                                                                  |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scripts/docker-smoke.sh`          | `docker compose up`, `curl` via SOCKS `127.0.0.1:11080` and HTTP proxy, `down`                                                                                                           |
| `scripts/udp-socks-smoke.sh`       | Ephemeral ports: TCP via SOCKS + **UDP DNS** (8.8.8.8:53) over SOCKS; fails if server/client dies at start                                                                               |
| `scripts/wsl-test.sh`              | Local smoke (plain/PSK) on WSL                                                                                                                                                           |
| `scripts/remote-deploy.sh`         | Reads parent `**server.txt`** (lines: IP, user, pass, SSH port): `tar` sync → local `cargo build` → `scp` binary → `**Dockerfile.server.binary**` on host → recreate `bibavpn` container |
| `scripts/remote-install-server.sh` | Build server image, `docker save`                                                                                                                                                        |
| `scripts/speedtest-via-socks.py`   | Speedtest via SOCKS (`pysocks`, `speedtest-cli`)                                                                                                                                         |
| `scripts/run-remote-speedtest.sh`  | SSH to VPS, venv, `speedtest-cli --simple` on the server (reads password/port from `server.txt` — gitignored)                                                                            |


**Remote entry, client in Docker (no compose file):** build `docker/Dockerfile.client`, then `docker run` with `-p` for SOCKS and HTTP proxy and the same flags as in the [example client](#build-and-run-local) above. Inside the container use matching `--socks5 0.0.0.0:<socks_port>` and `--http-proxy 0.0.0.0:<http_port>`; publish those ports on the host (e.g. `11090:11090`, `11880:18080`).

## UDP design note (agents)

The server keeps a **pending map** (by destination `SocketAddr`) to correlate **UDP_REP** to **UDP_REQ**. Under **many concurrent requests to the same** `IP:port`, replies could theoretically be matched out of order (same limitation as a naive single-socket demux). Hardening would be additional correlation (per-request id already exists as xid — verify end-to-end ordering guarantees if touching this).

## Security

- **Do not commit:** `server.txt`, `.env`, `.env.remote`, passwords, PEM keys (see `.gitignore`).
- Treat PSK and token as **secrets**; rotate and restart both ends on leak.
- Prefer **SSH keys** over long credentials in `server.txt` for `remote-deploy.sh`.
- Do not embed real credentials in docs or examples.

## Guidelines for agents

1. Touch only what the task needs; avoid unrelated refactors.
2. Match existing style (`clap`, `tracing`, async, imports).
3. Any BibaV2 wire change: update client **and** server plus tests.
4. After Docker/Compose edits, run `scripts/docker-smoke.sh`; after UDP changes, run `scripts/udp-socks-smoke.sh` (WSL/bash).
5. Use env vars and placeholders — never real IPs/passwords/PSK in the tree.

## Scenarios that were validated

- Local compose: SOCKS → `example.com`.
- Workstation client → remote server → HTTPS (including `api.telegram.org`).
- **SOCKS UDP** (DNS) via separate WSS mux (`udp-socks-smoke.sh`).
- Speedtest via SOCKS (`speedtest-via-socks.py` in a venv).
- Server/client images build with the Rust version pinned in the Dockerfiles; **remote** slim image via `Dockerfile.server.binary` on small disks.

---

*For humans and AI agents working on the BibaVPN repository.*