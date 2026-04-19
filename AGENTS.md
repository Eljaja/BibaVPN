# BibaVPN — context for agents and developers

This document is the fast-path briefing for humans and AI agents contributing
to BibaVPN. It covers what the project is, how the code is laid out, the CLI
knobs that actually matter on the wire, and the workflows you should follow
before proposing a change.

For on-wire byte layouts see **[PROTOCOL.md](PROTOCOL.md)**. For install / run
walkthroughs see **[README.md](README.md)**. For contributor etiquette see
**[CONTRIBUTING.md](CONTRIBUTING.md)**.

## Contents

- [What the project is](#what-the-project-is)
- [Repository layout](#repository-layout)
- [`bibavpn` crate modules](#bibavpn-crate-modules)
- [BibaV2 (short)](#bibav2-short)
- [Biba v3 (short)](#biba-v3-short)
- [BibaV2.1 and transport knobs](#bibav21-and-transport-knobs)
- [Build and run (local)](#build-and-run-local)
- [Docker / Compose gotcha](#docker--compose-gotcha)
- [Scripts](#scripts)
- [UDP design note (agents)](#udp-design-note-agents)
- [Testing and benchmarks](#testing-and-benchmarks)
- [Security](#security)
- [Guidelines for agents](#guidelines-for-agents)
- [Scenarios that were validated](#scenarios-that-were-validated)

## What the project is

**BibaVPN** is a proxy stack: local **SOCKS5** (TCP `CONNECT` and
`UDP ASSOCIATE`) and optional **HTTP CONNECT** → **TLS + WebSocket** → remote
entry server → outbound **TCP or UDP** to the Internet. Optionally **BibaV2**
(PSK, AEAD, decoy), **Biba v3** (opaque PSK hello/ACK, domain-separated KDF,
sealed control frames — backward compatible with v2), and **BibaV2.1**
transport knobs (WS ping, frame-size cap, custom headers, early noise) sit on
top of the transport.

**TCP — default:** many SOCKS connections share **one** TLS+WSS session
(**TCP mux** in `tcp_mux.rs`). After `AUTH` and the optional BibaV2 preamble,
the client sends `MUX_OPEN`; per-target opens use mux records (stream id,
flags, payload) inside padded frames, with window-based flow control. Use
`--no-mux` for legacy **one WSS per SOCKS CONNECT** (`OPEN` + binary loop).

**UDP** (e.g. DNS via SOCKS5 UDP) uses a **separate** shared WSS:
`UDP_MUX_OPEN` (`protocol.rs`), then `UDP_REQ` / `UDP_REP` (`udp_mux.rs`).
Same TLS/WebSocket fingerprint class as TCP from the client to the VPS.

**HTTP on the TLS port:** non-WebSocket requests are served as **camouflage**
(`incoming.rs`, `camouflage.rs`): nginx-style responses, optional
`--camouflage-dir` static files, or `--camouflage-url` (`http://host:port`
only — plaintext to origin).

**DPI-oriented options:** `--pad-mode random|http-buckets`,
`--dummy-interval-secs` (idle empty padded frames on the tunnel; mux shares
one outer connection), client-only decoy `--decoy-gets` (+ interval and
comma-separated paths), `stealth.rs` WebSocket upgrade header order per TLS
profile (Chrome / Firefox).

Typical traffic path (TCP, mux):

1. Application → **SOCKS5** (plain local hop).
2. Client opens **WSS** to the configured `--ws-path` (default `/ws`); the
   **token** travels in the `AUTH` binary (`protocol.rs`, `ws_auth.rs`), not
   in the URL.
3. Optional **BibaV2** HELLO/ACK and AEAD on frames.
4. `MUX_OPEN`, then stream `OPEN` / `DATA` / close; the server dispatches to
   per-stream TCP (`bridge_ws_tcp_mux_server`).

Typical path (UDP via SOCKS): `UDP ASSOCIATE` → shared `UdpMuxHandle` and a
dedicated WSS.

## Repository layout

| Path                         | Role                                                                         |
| ---------------------------- | ---------------------------------------------------------------------------- |
| `bibavpn/`                   | Core crate: `lib` plus `bibavpn-server`, `bibavpn-client`, `bibavpn-mint-invite` bins |
| `biba/`                      | Thin wrapper / helper crate used by bins and tests                           |
| `bibavpn-jni/`               | JNI bindings for the Android app (`nativeStart` and friends)                 |
| `bibavpn-desktop/`           | Tauri desktop wrapper (`src-tauri/` Rust + `ui/` web front-end)              |
| `android/`                   | Jetpack Compose Android app (Gradle)                                         |
| `docker/`                    | `Dockerfile.server`, `Dockerfile.server.binary`, `Dockerfile.client`         |
| `docker-compose.yml`         | Local lab: server + client on one Docker network                             |
| `docker-compose.hub.yml`     | Pull prebuilt images from Docker Hub for a quick start                       |
| `scripts/`                   | Smoke tests, deploy helpers, benchmarks, packet-capture labs                 |
| `docs/`                      | Static landing pages / extra documentation                                   |
| `branding/`                  | Logos and design assets (see also `DESIGN.md`)                               |
| `start.sh`                   | One-shot local server launcher; mints token/PSK/invite, runs compose         |
| `rust-toolchain.toml`        | Pinned stable Rust toolchain for reproducible builds                         |

## `bibavpn` crate modules

| Path                                                | Role                                                                                                                   |
| --------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `bibavpn/src/lib.rs`                                | Module exports                                                                                                         |
| `bibavpn/src/bin/server.rs`                         | TLS accept; **first-byte HTTP vs WS** via `incoming`; AUTH; `wait_first_channel` → TCP bridge, TCP mux, or UDP mux     |
| `bibavpn/src/bin/client.rs`                         | Client CLI; invite merge for `ws_path`, `pad_mode`, `dummy_interval_secs`, decoy flags                                 |
| `bibavpn/src/bin/mint_invite.rs`                    | `bibavpn-mint-invite`: print `biba://` with `INVITE_PROTO` / `INVITE_PROTO_DOMAIN` for v3 invites                      |
| `bibavpn/src/crypto_layer.rs`                       | BibaV2 + v3: BLAKE3 derive, v2 HELLO/ACK + v3 opaque hello/ACK, MAC, domain-aware `SessionCrypto`, decoy               |
| `bibavpn/src/incoming.rs`                           | Read HTTP request on TLS; WebSocket 101 + `WebSocketStream::from_partially_read`; or serve camouflage GET/HEAD         |
| `bibavpn/src/camouflage.rs`                         | Shared HTML / 404 bodies for rejects and static fallbacks                                                              |
| `bibavpn/src/ws_auth.rs`                            | Server waits for `AUTH` frame (timeout, skip noise)                                                                    |
| `bibavpn/src/tcp_mux.rs`                            | Mux wire format, client handle, server bridge, optional idle dummy on the mux                                          |
| `bibavpn/src/tcp_mux_roadmap.rs`                    | Long-form design notes for the TCP-mux evolution (no runtime code)                                                     |
| `bibavpn/src/decoy_traffic.rs`                      | Optional parallel short HTTPS GETs (same TLS profile as the tunnel)                                                    |
| `bibavpn/src/socks5.rs`                             | SOCKS5 frontend (`CONNECT` + `UDP ASSOCIATE` replies)                                                                  |
| `bibavpn/src/local_client.rs`                       | SOCKS dispatch, mux slot, UDP mux, decoy spawn, `LocalClientOptions`                                                   |
| `bibavpn/src/udp_mux.rs`                            | Client driver + `bridge_ws_udp_mux_server`; padded frames + optional `pad_mode`                                        |
| `bibavpn/src/protocol.rs`                           | `OPEN`, `AUTH`, `UDP_MUX_OPEN`, `UDP_REQ`/`UDP_REP`, ATYP helpers                                                      |
| `bibavpn/src/tls_util.rs`, `frame.rs`, `stealth.rs` | TLS profiles, `PadMode`, WS upgrade (ordered headers, UA / Sec-CH)                                                     |
| `bibavpn/src/ws_bridge.rs`                          | WebSocket ↔ TCP bridge (legacy per-connection TCP); ping + dummy task; `pad_mode`                                      |
| `bibavpn/src/http_connect.rs`                       | HTTP `CONNECT` on a separate listen port                                                                               |
| `bibavpn/src/invite_uri.rs`                         | `InviteV1`: `proto` (default `2`), optional `proto_domain`, plus `ws_path`, `pad_mode`, `dummy_interval_secs`          |
| `bibavpn/src/start_json_config.rs`                  | JSON start config (same shape used by Android `nativeStart` / `bibavpn-jni`)                                           |
| `bibavpn/src/retry.rs`                              | Exponential backoff between outbound TCP+TLS+WSS attempts and optional WS timing jitter                                |
| `bibavpn/src/outbound_protect.rs`                   | Hook for marking outbound TCP sockets before `connect` (Android `VpnService.protect`)                                  |

## BibaV2 (short)

- Enabled with matching `--psk` and `--decoy-max` on client and server.
- HELLO: magic `BIBV2HL1` + 32-byte client random.
- ACK: `BIBV2ACK1` + server random + 16-byte keyed MAC (BLAKE3 over PSK).
- Directional keys: `bibavpn.v2.c2s` / `bibavpn.v2.s2c`.
- On the wire: 12-byte nonce + ciphertext; plaintext is optional decoy
  `0..N` bytes followed by the **inner payload** (padded frame or mux record,
  etc.).
- Unit tests in `crypto_layer`, `frame`, `protocol` (AUTH); wire-format
  changes need client **and** server updates.

## Biba v3 (short)

- **Requires PSK** on both ends. Client selects v3 with `--proto 3` or
  invite `proto: 3`.
- **Handshake (NewPath):** the first meaningful client Binary after optional
  noise is either legacy `AUTH` (v2 token path) or `0x03` + 32 B client
  random (opaque hello). Server answers v3 with 32 B server random + 16 B
  MAC (no ASCII ACK magic). MAC and session keys use a **domain string**
  mixed into the KDF (`bibavpn.v3.mac.psk`, `bibavpn.v3.c2s`,
  `bibavpn.v3.s2c`).
- **Server:** `--proto-domain <label>` (default `default`; must not be empty
  after trim). **Client / invite:** `--proto-domain` or `proto_domain` in
  JSON; if the client field is empty, the effective domain is the **SNI**
  string — it must match what the server uses.
- **Control plane** (`AUTH`, TCP `OPEN` / `OPEN_OK` / `OPEN_ERR`,
  `MUX_OPEN`, `UDP_MUX_OPEN`): inner **single-byte opcodes** + payloads,
  carried **inside AEAD** after the handshake — not the plaintext
  `BIBA\x01…` magics used in v2 for those steps.
- **Data plane:** same padded inner frames and mux/UDP records as v2.
  `UDP_REQ` / `UDP_REP` still use the legacy `BIBA…` inner layout inside the
  ciphertext (handshake is v3; datagram magics not yet migrated).
- `--print-invite-uri` today still emits `proto: 2` and omits `proto_domain`.
  For v3 invites use `bibavpn-mint-invite` with `INVITE_PROTO=3` and optional
  `INVITE_PROTO_DOMAIN`, or hand-edit JSON before sealing.

## BibaV2.1 and transport knobs

Compatible with the same BibaV2 PSK/decoy when both ends match.

- `--ws-ping-secs`, `--ws-ping-jitter-percent`, `--ws-binary-send-jitter-ms`
- `--max-ws-binary` — cap outgoing WS binary (see
  `frame::max_tcp_payload_per_ws_message`; mux code reserves **9 bytes** for
  the mux record header when chunking TCP).
- `--udp-max-pad`, `--udp-max-ws-binary`, `--udp-mux-reply-timeout-secs`
  (client), `--udp-mux-recv-timeout-secs` (server)
- `--ws-host`, `--ws-origin`, `--ws-user-agent`, `--ws-accept-language`,
  `--ws-header` (repeatable `Name: value`)
- `--early-ws-frames`, `--junk-frames`
- `--pin-cert` (client) — incompatible with `--insecure`
- `--ws-path` / server `--ws-path` — WebSocket path; token via `AUTH`
  (default `/ws`)
- Client `--proto` (`2` default, `3` = v3) and `--proto-domain` (v3 KDF
  label; empty → SNI)
- Server `--proto-domain` — v3 KDF label (default `default`); must match
  clients using v3
- Server `--legacy-path-auth` — accept the old `/b/{token}` URL without
  `AUTH` (less safe)
- `--pad-mode random|http-buckets` — padding distribution (invite may carry
  `pad_mode` string)
- `--dummy-interval-secs` — idle empty padded frames (`0` = off); invite may
  set `dummy_interval_secs`
- Client `--decoy-gets`, `--decoy-gets-interval-secs`,
  `--decoy-gets-paths` — not part of invite JSON (client-only)
- Server `--camouflage-dir`, `--camouflage-url` (`http://` upstream only)

`rust-toolchain.toml` pins a stable Rust version for reproducible builds.
Docker images use a matching or newer toolchain.

Wire layouts (padded frame, BibaV2, `AUTH`, `OPEN`, mux, UDP mux) are in
**[PROTOCOL.md](PROTOCOL.md)**.

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

**Note:** `--insecure` and self-signed certificates are for **tests only**.
Production: real certificates (e.g. Let's Encrypt behind a reverse proxy) and
no `--insecure`.

For a turnkey local lab, `bash start.sh` mints a token, PSK and invite
passphrase, writes them to `.biba-start.env`, and brings the server up via
`docker compose`. It also prints a `biba://…` invite URI that the desktop /
Android apps can paste.

## Docker / Compose gotcha

`Dockerfile.*` sets `ENTRYPOINT` to the binary path. In `docker-compose.yml`,
`command:` must list **argument flags only** (do not repeat the binary path).
Otherwise `clap` sees an extra token and the container exits with code 2.

**Small VPS / low disk:** build locally (e.g. in WSL) and use
`docker/Dockerfile.server.binary` — see `scripts/remote-deploy.sh`.

## Scripts

The `scripts/` directory is a grab bag. The ones most useful when working on
BibaVPN:

| Script                             | Purpose                                                                                                 |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `scripts/docker-smoke.sh`          | `docker compose up`, `curl` via SOCKS and HTTP proxy, `down`                                            |
| `scripts/udp-socks-smoke.sh`       | TCP via SOCKS + UDP DNS over SOCKS                                                                      |
| `scripts/wsl-test.sh`              | Local smoke (plain / PSK) on WSL                                                                        |
| `scripts/wsl-proto-v3-smoke.sh`    | WSL: v3 then v2 TCP via SOCKS + `curl` (needs release binaries + `openssl`, `python3`, `fuser`)         |
| `scripts/wsl-local-bench.sh`       | 64 MiB HTTP direct vs SOCKS+WSS throughput (run in WSL from repo root)                                  |
| `scripts/wsl-udp-socks-bench.sh`   | SOCKS UDP throughput bench on WSL                                                                       |
| `scripts/remote-deploy.sh`         | Sync + build + `Dockerfile.server.binary` deploy                                                        |
| `scripts/remote-install-server.sh` | Build the server image and `docker save` it                                                             |
| `scripts/speedtest-via-socks.py`   | Speedtest via SOCKS                                                                                     |
| `scripts/run-remote-speedtest.sh`  | SSH + `speedtest-cli` on the VPS                                                                        |
| `scripts/bibavpn_e2e.py`           | End-to-end test harness (Python)                                                                        |
| `scripts/bibavpn_public_probe.py`  | Probe a public endpoint for basic reachability                                                          |
| `scripts/wsl-pcap-*.py`            | Packet-capture / DPI behavior labs (see the individual headers)                                         |

**Remote client in Docker:** build `docker/Dockerfile.client`, then
`docker run` with published SOCKS/HTTP proxy ports; use `0.0.0.0` binds
inside the container.

## UDP design note (agents)

The server keeps a **pending map** (by destination `SocketAddr`) to correlate
`UDP_REP` to `UDP_REQ`. Under many concurrent requests to the same
`IP:port`, ordering assumptions matter (`xid` is per datagram).

## Testing and benchmarks

- Unit and integration tests live alongside the code in `bibavpn/src/…`.
  Run the whole workspace with:

  ```bash
  cargo test --workspace
  ```

- `scripts/docker-smoke.sh` is the cheapest end-to-end check that nothing
  regressed at the TLS+WSS layer.
- `scripts/wsl-proto-v3-smoke.sh` exercises both v3 and v2 handshakes on
  release binaries — run it after any change to `crypto_layer.rs`,
  `ws_auth.rs`, `protocol.rs`, or the `--proto*` CLI flags.
- `scripts/wsl-local-bench.sh` is a quick sanity check for throughput after
  changes to `frame.rs`, `tcp_mux.rs`, or `ws_bridge.rs`.

## Security

- **Do not commit:** `server.txt`, `.env`, passwords, PEM keys (see
  `.gitignore`).
- Treat PSK, token, and invite passphrase as **secrets**.
- `--pin-cert` narrows trust; do not combine with `--insecure` on the
  client.
- Prefer **SSH keys** for `remote-deploy.sh`.
- Do not embed real credentials in docs or examples.

See **[SECURITY.md](SECURITY.md)** for the disclosure policy.

## Guidelines for agents

1. Touch only what the task needs; avoid unrelated refactors.
2. Match existing style (`clap`, `tracing`, async, imports).
3. Any wire-format change: update client **and** server plus tests; keep
   **[PROTOCOL.md](PROTOCOL.md)** in sync for on-wire layouts, and mirror
   the user-facing description into **[README.md](README.md)** if it
   affects the CLI.
4. After Docker / Compose edits, run `scripts/docker-smoke.sh`; after UDP
   changes, `scripts/udp-socks-smoke.sh`; for throughput sanity,
   `scripts/wsl-local-bench.sh` (WSL).
5. Use placeholders — never real IPs / passwords / PSKs in the tree.
6. Prefer small, focused commits with descriptive messages; leave unrelated
   formatting alone.

## Scenarios that were validated

- Local compose: SOCKS → example hosts.
- Workstation client → remote server → HTTPS.
- SOCKS UDP (DNS) via UDP mux (`scripts/udp-socks-smoke.sh`).
- WSL local bench: direct HTTP vs SOCKS+WSS 64 MiB
  (`scripts/wsl-local-bench.sh`).
- WSL v3 + v2 regression (`scripts/wsl-proto-v3-smoke.sh`): release
  server/client, SOCKS `curl` over v3 then v2.
- Speedtest via SOCKS (`scripts/speedtest-via-socks.py` in a venv).
- Server/client images and slim remote image via
  `docker/Dockerfile.server.binary`.

---

*For humans and AI agents working on the BibaVPN repository.*
