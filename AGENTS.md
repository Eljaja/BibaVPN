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
- [PSK tunnel wire (proto 3)](#psk-tunnel-wire-proto-3)
- [Transport and WebSocket knobs](#transport-and-websocket-knobs)
- [Build and run (local)](#build-and-run-local)
- [Server limits (hardening)](#server-limits-hardening)
- [Docker / Compose gotcha](#docker--compose-gotcha)
- [Scripts](#scripts)
- [UDP design note (agents)](#udp-design-note-agents)
- [Testing and benchmarks](#testing-and-benchmarks)
- [Security](#security)
- [Stealth, DPI, and roadmap](#stealth-dpi-and-roadmap)
- [Logging (tracing)](#logging-tracing)
- [Guidelines for agents](#guidelines-for-agents)
- [Scenarios that were validated](#scenarios-that-were-validated)

## What the project is

**BibaVPN** is a proxy stack: local **SOCKS5** (TCP `CONNECT` and
`UDP ASSOCIATE`) and optional **HTTP CONNECT** → **TLS + WebSocket** → remote
entry server → outbound **TCP or UDP** to the Internet.

The tunnel crypto on the wire is **proto 3**: shared **PSK**, opaque
variable-length HELLO/ACK, ChaCha20-Poly1305, domain-separated KDF, sealed
control opcodes, and inner UDP records in the same framing.

That **proto-3** layout is carried over **TLS + WebSocket**; optional **stealth**
layers sit on the outside (TLS client profile labels, padding modes, timing,
decoys, optional multi-WSS, optional BoringSSL). **Future inner opcodes / framing**
may evolve — see the roadmap section in **[PROTOCOL.md](PROTOCOL.md#target-specification-roadmap)**
for targets that are not fully implemented here yet.

**WebSocket transport** knobs (ping, frame-size cap, custom headers, early noise)
apply on the outer path. **Stealth / DPI-oriented** options include
`PadMode::Adaptive`, `--stealth-profile`, `--fingerprint` / TLS resolution order,
WebSocket jitter, parallel outer WSS sessions (`--ws-parallel`), idle-triggered
decoys, server delayed-ACK / RTT masking, and an optional **BoringSSL** build
(`--features boring-tls`, `--tls-stack boring`).

**TCP — default:** many SOCKS connections share **one or more** TLS+WSS sessions
(**TCP mux** in `tcp_mux.rs`). With `--ws-parallel 2..=4`, the client opens that
many full tunnel sessions (each with `MUX_OPEN`) and **round-robins** new streams
across them (`TcpMuxSessionPool::pick`). After HELLO/ACK and sealed **AUTH**,
the client sends `MUX_OPEN`; per-target opens use mux records (stream id, flags,
payload) inside padded frames, with window-based flow control. Use `--no-mux` for
legacy **one WSS per SOCKS CONNECT** (`OPEN` + binary loop). **REALITY** mode uses
the same `**--ws-parallel` 1..=4** pattern: each outer link runs TLS + WSS +
REALITY (X25519 + client AUTH) handshake, then `MUX_OPEN`; the pool **round-robins** new streams
(`connect_reality_tcp_mux_handle` in `local_client.rs`).

**UDP** (e.g. DNS via SOCKS5 UDP) uses a **separate** shared WSS:
`UDP_MUX_OPEN` (`protocol.rs`), then inner `**0x05` UDP_REQ** / `**0x06` UDP_REP**
records (`udp_mux.rs`). Same TLS/WebSocket fingerprint class as TCP from the
client to the VPS.

**HTTP on the TLS port:** non-WebSocket requests are served as **camouflage**
(`incoming.rs`, `camouflage.rs`): nginx-style responses, optional
`--camouflage-dir` static files, or `--camouflage-url` (`http://host:port`
only — plaintext to origin).

**DPI-oriented options:** `--pad-mode adaptive|random|http-buckets`,
`--dummy-interval-secs` (idle empty padded frames on the tunnel; mux may share
several outer connections when `--ws-parallel` is between 2 and 4), **TLS profile** via
`--fingerprint` / `--tls-profile` (priority rules in `client_policy.rs` —
default client label **Chrome 132+** when nothing else applies), optional
`--stealth-profile default|balanced|aggressive` (fills pad/jitter/decoy/idle
thresholds when explicit flags are absent), **WebSocket send jitter** (`--ws-jitter-min/max-ms`
or legacy uniform delay), **idle decoy** HTTPS GETs when the mux is quiet longer
than `--idle-decoy-secs` (merged with preset; **10 s** in balanced/aggressive
presets unless overridden) — `activity.rs` + `decoy_traffic.rs`, client-only
parallel decoy `--decoy-gets` (+ interval and paths), decoy presets in `stealth_v12.rs`,
`stealth.rs` WebSocket upgrade header shape per `TlsClientProfile`. **Server:**
`--server-ack-delay-*-ms`, `--rtt-mask-jitter-ms`, and optional `--ack-profile balanced|aggressive` when the explicit millisecond args are all zero
(`ServerRttDefaults` in `stealth_v12.rs`). **Outer TLS engine:** `rustls` (default,
`biba` cipher/ALPN hints) or **BoringSSL** (`cargo build -p bibavpn --features boring-tls`,
client `--tls-stack boring`); **`--pin-cert`** works on **both** stacks (leaf DER match on
Boring via `tls_boring.rs`). **Raw desync** (`desync.rs` — re-exports `effective_desync_mode` /
`DesyncApplied` from `transport_capabilities.rs`): split / disorder / fake
handshake are **mostly advisory** until raw-socket or external helpers (e.g.
zapret) participate; see **[PROTOCOL.md](PROTOCOL.md)** / **[README.md](README.md)**
for the operator story.

**REALITY (WSS path):** optional front-domain mode — outer **TLS SNI** follows
`reality_target` (e.g. `vk.com`), then **WSS upgrade**, then **X25519** binary frames on the
WebSocket (`reality.rs`), then a **mandatory client AUTH frame**, then **plaintext** `MUX_OPEN`
(no v3 PSK on that TCP path). This is
**not** Xray-style TLS ClientHello stealing; see **[PROTOCOL.md — REALITY](PROTOCOL.md#reality-wss-path)**.
Server: `--reality-target`, `--reality-private-key`, optional `--reality-short-ids` (SpiderX
background fetch runs when REALITY is enabled; a missing/all-zeros allowlist accepts any short ID and
logs a `WARN` at startup). Client / invite: `reality_target`,
`reality_public_key`, `reality_short_id`. Outer TLS may use **rustls** or **boring** (same as
non-REALITY). Test: `cargo test -p bibavpn --test reality_handshake`.

**REALITY client AUTH is required** in every REALITY session, on both the `MUX_OPEN` and the
REALITY + v3 (UDP mux) sub-paths: `[version:1][0xa1][mac:32]` right after `SERVER_HELLO`, where the
MAC is keyed BLAKE3 over `client_ephemeral_pub || server_pub` keyed by `shared_secret || token`
(`reality_client_auth_mac`). The X25519 exchange only authenticates the **server**, so before this
frame existed the REALITY TCP path was an **open proxy**. The token is never sent on the wire; the
server compares in constant time and records failures with the auth rate limiter, like a v3 AUTH
mismatch. Adding a frame does not change the HELLO / SERVER_HELLO layout, so `REALITY_VERSION`
stays `2` — but old and new peers no longer interoperate on the REALITY path. On **REALITY + v3 PSK**,
ChaCha20-Poly1305 transport keys also mix the REALITY X25519 shared secret (not the HELLO ACK MAC);
client and server must ship together on that path.

Typical traffic path (TCP, mux):

1. Application → **SOCKS5** (plain local hop).
2. Client opens **WSS** to the configured `--ws-path` (default `/ws`); the
  **token** is sent in a **sealed AUTH** frame after HELLO/ACK (`protocol.rs`,
   `local_client.rs` / `server.rs`), not in the URL.
3. HELLO/ACK (**proto 3**), then ChaCha20-Poly1305 on frames.
4. `MUX_OPEN`, then stream `OPEN` / `DATA` / close; the server dispatches to
  per-stream TCP (`bridge_ws_tcp_mux_server`).

Typical path (UDP via SOCKS): `UDP ASSOCIATE` → shared `UdpMuxHandle` and a
dedicated WSS.

## Repository layout


| Path                     | Role                                                                                  |
| ------------------------ | ------------------------------------------------------------------------------------- |
| `bibavpn/`               | Core crate: `lib` plus `bibavpn-server`, `bibavpn-client`, `bibavpn-mint-invite` bins |
| `biba/`                  | Thin wrapper / helper crate used by bins and tests                                    |
| `apps/`                  | Tauri client apps, Android VPN glue, JNI / iOS FFI crates, scripts                    |
| `apps/bibavpn-jni/`      | JNI bindings for Android (`nativeStart` and friends); crate `bibavpn-jni`             |
| `apps/bibavpn-ffi/`      | C ABI static library for iOS Packet Tunnel; crate `bibavpn-ffi`                       |
| `apps/bibavpn-desktop/`  | Tauri desktop/Android/iOS wrapper (`src-tauri/` Rust + `ui/` web front-end)           |
| `apps/scripts/`          | Shell/PowerShell helpers for Tauri/Android/iOS bootstrap, JNI, WSL builds             |
| `docker/`                | `Dockerfile.server`, `Dockerfile.server.binary`, `Dockerfile.client`                  |
| `docker-compose.yml`     | Local lab: server + client on one Docker network                                      |
| `docker-compose.hub.yml` | Pull prebuilt images from Docker Hub for a quick start                                |
| `scripts/`               | Server/client smoke tests, deploy helpers, benchmarks, packet-capture labs            |
| `docs/`                  | Static landing pages / extra documentation                                            |
| `branding/`              | Logos and design assets (see also `DESIGN.md`)                                        |
| `start.sh`               | One-shot local server launcher; mints token/PSK/invite, runs compose                  |
| `rust-toolchain.toml`    | Pinned stable Rust toolchain for reproducible builds                                  |


Full layout for `**apps/`** (desktop, Android, JNI crate, scripts): **[apps/AGENTS.md](apps/AGENTS.md)**.

## `bibavpn` crate modules


| Path                                                | Role                                                                                                               |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `bibavpn/src/lib.rs`                                | Module exports                                                                                                     |
| `bibavpn/src/bin/server.rs`                         | TLS accept; **first-byte HTTP vs WS** via `incoming`; AUTH; `wait_first_channel` → TCP bridge, TCP mux, or UDP mux |
| `bibavpn/src/bin/client.rs`                         | Client CLI; invite merge for `ws_path`, `pad_mode`, `dummy_interval_secs`, decoy flags                             |
| `bibavpn/src/bin/mint_invite.rs`                    | `bibavpn-mint-invite`: print `biba://` (`INVITE_PROTO` / `INVITE_PROTO_DOMAIN`; defaults match `--proto 3`)                 |
| `bibavpn/src/crypto_layer.rs`                       | Proto-3 tunnel: BLAKE3 derive, opaque HELLO/ACK (variable trailing padding), MAC, domain-aware `SessionCrypto` (per-direction **AtomicU64** nonces; `Sync` seal/open), decoy |
| `bibavpn/src/incoming.rs`                           | Read HTTP request on TLS; WebSocket 101 + `WebSocketStream::from_partially_read`; or serve camouflage GET/HEAD     |
| `bibavpn/src/camouflage.rs`                         | Shared HTML / 404 bodies for rejects and static fallbacks                                                          |
| `bibavpn/src/ws_auth.rs`                            | Server waits for sealed `AUTH` (timeout, pre-`AUTH` junk/decrypt budgets via `PreAuthBudget` in `server_limits.rs`)   |
| `bibavpn/src/tcp_mux.rs`                            | Mux wire format, client handle, server bridge, optional idle dummy, multi-WSS pool + RR                            |
| `bibavpn/src/tcp_mux_roadmap.rs`                    | **Historical** one-WSS mux sketch; **current** implementation is `tcp_mux.rs` (doc-only module)                    |
| `bibavpn/src/reality.rs`                              | WSS REALITY: X25519 exchange, mandatory client AUTH MAC (`reality_client_auth_mac`), SpiderX, `effective_tls_sni`, invite fields                     |
| `bibavpn/src/client_tls_stream.rs`, `tls_boring.rs` | `TlsStack` paths: `rustls` (default) vs `boring` (`--features boring-tls`); REALITY + Boring; **`--pin-cert`** on both; Boring **`--tls-fragment`** via `SSL_CTX_set_max_send_fragment` |
| `bibavpn/src/client_policy.rs`                      | TLS client label resolution: `fingerprint` → `tls_profile` → invite → `stealth` → default **Chrome 132+**          |
| `bibavpn/src/stealth_v12.rs`                        | `StealthProfile` / presets (pad, jitter, decoys, idle threshold, server RTT defaults)                              |
| `bibavpn/src/activity.rs`                           | Idle detection for idle-decoy scheduling                                                                           |
| `bibavpn/src/decoy_traffic.rs`                      | Optional parallel short HTTPS GETs (same TLS profile as the tunnel)                                                |
| `bibavpn/src/socks5.rs`                             | SOCKS5 frontend (`CONNECT` + `UDP ASSOCIATE` replies)                                                              |
| `bibavpn/src/local_client.rs`                       | SOCKS dispatch, mux slot, UDP mux, decoy spawn, `LocalClientOptions`                                               |
| `bibavpn/src/udp_mux.rs`                            | Client driver + `bridge_ws_udp_mux_server`; multi-addr `resolve_udp_dest`, client **xid** collision handling, optional server `UdpSocketPool` |
| `bibavpn/src/protocol.rs`                           | Proto-3 sealed opcodes, `UDP_MUX_OPEN`, `UDP_REQ`/`UDP_REP` (`0x05`/`0x06`), ATYP helpers                            |
| `bibavpn/src/tls_util.rs`, `frame.rs`, `stealth.rs` | Cipher/ALPN + `TlsStack` + record-fragment notes (`tls_util.rs`); `PadMode`; WS upgrade (UA / Sec-CH / `Accept-Language`) |
| `bibavpn/src/server_limits.rs`                      | `AuthRateLimiter`, `PreAuthBudget`, `ServerStats` / `SessionGuard`                                                 |
| `bibavpn/src/server_metrics.rs`                     | Prometheus text render + optional HTTP `/metrics` and `/healthz` on `--metrics-listen`; optional `--metrics-password` Basic Auth |
| `bibavpn/src/transport_capabilities.rs`             | `log_server_listen_caps` / `log_client_transport_caps`; effective desync helpers                                    |
| `bibavpn/src/logging.rs`                           | Tracing init (`LogConfig`, idempotent second init); `bibavpn/src/log_ratelimit.rs` — hot-path log cadence          |
| `bibavpn/src/desync.rs`                            | TCP post-connect hints, TLS fragment notes, decoy RTT jitter; **re-export** `effective_desync_mode`, `DesyncApplied` |
| `bibavpn/src/ws_bridge.rs`                          | WebSocket ↔ TCP bridge (legacy per-connection TCP); ping + dummy task; `pad_mode`                                  |
| `bibavpn/src/http_connect.rs`                       | HTTP `CONNECT` on a separate listen port                                                                           |
| `bibavpn/src/invite_uri.rs`                         | Invite encoding (`InviteV1` type): `proto` (default `3`), optional `proto_domain`, plus `ws_path`, `pad_mode`, `dummy_interval_secs`      |
| `bibavpn/src/start_json_config.rs`                  | JSON start config (same shape used by Android `nativeStart` / `apps/bibavpn-jni`)                                  |
| `bibavpn/src/retry.rs`                              | Exponential backoff between outbound TCP+TLS+WSS attempts and optional WS timing jitter                            |
| `bibavpn/src/outbound_protect.rs`                   | Hook for marking outbound TCP sockets before `connect` (Android `VpnService.protect`)                              |


## PSK tunnel wire (proto 3)

- **Requires PSK** on both ends. Client `**--proto`** defaults to `**3**`; invites
default to `**proto: 3**`.
- **Handshake:** after optional noise, the first client Binary is **HELLO** (proto 3):
`0x03` ∥ 32 B client random ∥ `pad_len` ∥ up to 64 B random padding (total
length is **not** fixed). Server **ACK**: 32 B server random ∥ 16 B MAC ∥
`pad_len` ∥ up to 64 B padding. MAC and session keys use a **domain string**
in the KDF (`bibavpn.v3.mac.psk`, `bibavpn.v3.c2s`, `bibavpn.v3.s2c`).
- **Server:** `--proto-domain <label>` (default `default`; must not be empty
after trim). **Client / invite:** `--proto-domain` or `proto_domain` in JSON;
if empty, the effective domain is the **SNI** — it must match the server.
- **Control plane** (`AUTH`, TCP `OPEN` / `OPEN_OK` / `OPEN_ERR`, `MUX_OPEN`,
`UDP_MUX_OPEN`): inner **single-byte opcodes** + payloads, **inside AEAD**
after the handshake (see `encode_v3_*` / `decode_v3_*` in `protocol.rs`).
- **UDP datagrams:** inner layout starts with `**0x05` (REQ)** or `**0x06` (REP)**,
then `xid`, SOCKS-like ATYP host/port, payload — not ASCII `BIBA…` magics.
- `**--print-invite-uri`** embeds `**proto: 3**` (same defaults as
`bibavpn-mint-invite`).
- Unit tests in `crypto_layer`, `frame`, `protocol`; wire-format changes need  
client **and** server updates.

## Transport and WebSocket knobs

- `--ws-ping-secs`, `--ws-ping-jitter-percent`, `--ws-binary-send-jitter-ms`
- `--max-ws-binary` — cap outgoing WS binary (see
`frame::max_tcp_payload_per_ws_message`; mux code reserves **9 bytes** for
the mux record header when chunking TCP).
- `--udp-max-pad`, `--udp-max-ws-binary`, `--udp-mux-reply-timeout-secs`
(client), `--udp-mux-recv-timeout-secs` (server)
- `--ws-host`, `--ws-origin`, `--ws-user-agent`, `--ws-accept-language`,
`--ws-header` (repeatable `Name: value`)
- `--early-ws-frames`, `--junk-frames`
- `--pin-cert` (client) — incompatible with `--insecure`; supported on **rustls** and **boring** (`boring-tls` build)
- `--reality-target`, `--reality-public-key`, `--reality-short-id` (client) — WSS REALITY front mode; invite JSON mirrors these fields
- Server **REALITY:** `--reality-target vk.com:443`, `--reality-private-key` (base64 X25519 seed, 32 bytes), `--reality-short-ids` (hex, comma-separated; empty = any + startup `WARN`; all-zero entry = wildcard + startup `WARN`), `--reality-server-names` (optional SNI allowlist; default = host from target). `--token` is **required** on the REALITY path too: it keys the client AUTH MAC.
- `--ws-path` / server `--ws-path` — WebSocket path; token via `AUTH`
(default `/ws`)
- Client `--proto` (only `**3`** is supported) and `--proto-domain` (KDF label;
empty → SNI)
- Server `--proto-domain` — KDF domain string for proto 3 (default `default`); must match
clients using the same `--proto` / invite
- Server `--legacy-path-auth` — accept the old `/b/{token}` URL without
`AUTH` (**deprecated**: standard path + sealed tunnel `AUTH` only in production)
- `--pad-mode adaptive|random|http-buckets` — padding distribution (invite may carry
`pad_mode` string); `--stealth-profile` can choose defaults when explicit
`pad_mode` / jitter / decoy args are unset
- `--dummy-interval-secs` — idle empty padded frames (`0` = off); invite may
set `dummy_interval_secs`
- Client `--decoy-gets`, `--decoy-gets-interval-secs`,
`--decoy-gets-paths` — not part of invite JSON (client-only)
- `--ws-parallel` **1..=4** — parallel outer WSS sessions + mux RR (ordinary TLS and **REALITY**)
- `--ws-jitter-min-ms` / `--ws-jitter-max-ms` (or legacy `--ws-binary-send-jitter-ms`)
- `--idle-decoy-secs` — background HTTPS when mux idle (merged with preset;
balanced/aggressive default **10 s** unless overridden)
- `--tls-stack rustls|boring` — build with `cargo build -p bibavpn --features boring-tls`
  for Boring; **`--pin-cert`** works on both stacks
- Client `--tls-fragment` — **Boring** path lowers max TLS record size via
`SSL_CTX_set_max_send_fragment` (`tls_boring.rs`); on **rustls** the client logs
that record splitting is not implemented (`desync::note_tls_fragment_requested`)
- **Server:** `--ack-profile balanced|aggressive` if explicit `--server-ack-`* /
`--rtt-mask-jitter-ms` are all zero; else set delays in milliseconds directly
- **Server:** `--handshake-timeout-secs` (per pre-tunnel phase: TLS accept, WS
upgrade / camouflage HTTP head, REALITY exchange, HELLO…`AUTH`; default **15**),
`--mux-connect-timeout-secs` (per mux stream outbound TCP connect, default **10**)
- Server `--camouflage-dir`, `--camouflage-url` (`http://` upstream only)
- **Logging (CLI):** server and client `--log-level`, `--log-format plain|json`;
server optional `--log-filter` (full `tracing_subscriber` directive when you need
more than the default target set)

`rust-toolchain.toml` pins a stable Rust version for reproducible builds.
Docker images use a matching or newer toolchain.

Wire layouts (padded frame, proto-3 crypto, sealed `AUTH`, `OPEN`, mux, UDP records) are in
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

## Server limits (hardening)

These are **server** `bibavpn-server` knobs from `bin/server.rs` (startup also
logs a one-line summary via `transport_capabilities::log_server_listen_caps`):

- **`--max-concurrent-sessions`** — default **512**; limits how many inbound
  connections may proceed past accept into **TLS + full session** handling at
  once (`tokio::sync::Semaphore`). **`0` disables** the cap (not recommended on
  small VPS without other protection). When the semaphore is saturated, a new
  accept waits **up to 5 seconds** for a permit; if none is available, the TCP
  is dropped and a `bibavpn_security` line records the timeout (server busy).
- **`--no-auth-rate-limit`** / **`--auth-max-failures`** /
  **`--auth-failure-window-secs`** / **`--auth-ban-secs`** — per-source limits
  on failed tunnel `AUTH` (see `server_limits::AuthRateLimiter`). Counted per
  bucket, **IPv4 /32** and **IPv6 /64** (`server_limits::auth_limit_key`), so a
  routed IPv6 prefix cannot rotate source addresses to dodge the ban.
- **`--handshake-max-junk-bytes`** (+ internal frame/decrypt budgets) — bounds
  pre-`AUTH` noise before `AUTH` completes (`server_limits::PreAuthBudget`).
- **`--udp-socket-pool-size`** — reuse up to N UDP sockets on the UDP mux path
  (`udp_mux::UdpSocketPool`); `0` keeps bind-per-datagram behavior.

Separate **mux** stream counts and SOCKS concurrency on the client are not this
semaphore; this cap is **outer TLS/WSS sessions** (and the work tied to each
accepted connection until it finishes).

**Other server timeouts / telemetry:**

- **`--handshake-timeout-secs`** — drop inbound sessions that stall in any
  pre-tunnel phase (default **15**, applied per phase): TLS accept, WebSocket
  upgrade / camouflage HTTP head, REALITY exchange and its first application
  frame, and the HELLO…`AUTH` wait. The concurrency permit is taken before any
  peer I/O, so without this a silent socket would hold a session slot; expiry
  counts in `bibavpn_handshake_timeouts_total` and releases the permit.
- **`--mux-connect-timeout-secs`** — limit how long the server waits on each
  outbound **TCP connect** for a mux stream (default **10**).
- **`--stats-interval-secs`** — periodic aggregate stats on the `bibavpn_server`
  target (`0` = disabled).
- **`--log-filter`** — optional `tracing_subscriber::EnvFilter` string; when set,
  it replaces the default `--log-level` directive for the process (see
  `logging::init` in `logging.rs`).

## Docker / Compose gotcha

`Dockerfile.*` sets `ENTRYPOINT` to the binary path. In `docker-compose.yml`,
`command:` must list **argument flags only** (do not repeat the binary path).
Otherwise `clap` sees an extra token and the container exits with code 2.

**Small VPS / low disk:** build locally (e.g. in WSL) and use
`docker/Dockerfile.server.binary` — see `scripts/remote-deploy.sh`.

## Scripts

### Client apps (`apps/`)

Desktop/Android (Tauri) and shell helpers for JNI / Tauri Android gen live under `**apps/`**. See **[apps/AGENTS.md](apps/AGENTS.md)** for layout and workflows.


| Path                                                   | Purpose                                                                          |
| ------------------------------------------------------ | -------------------------------------------------------------------------------- |
| `apps/scripts/tauri-android-init-local.sh`             | Run `tauri android init --ci` locally (or via Docker wrapper in the same folder) |
| `apps/scripts/integrate-bibavpn-into-tauri-android.sh` | Merge Android VPN extras into Tauri `gen/android`                                |
| `apps/scripts/wsl-build-tauri-android-jni.sh`          | Build `libbibavpn_jni.so` into Tauri gen `jniLibs` (`cargo-ndk`)                 |
| `apps/scripts/wsl-build-rust-apk.sh`                   | Compatibility wrapper for the Tauri Android APK build                            |


### Repository-wide helpers (`scripts/`)

The `scripts/` directory is a grab bag. The ones most useful when working on
BibaVPN:


| Script                              | Purpose                                                                                                                                                        |
| ----------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scripts/docker-smoke.sh`           | `docker compose up`, `curl` via SOCKS and HTTP proxy, `down`                                                                                                   |
| `scripts/udp-socks-smoke.sh`        | TCP via SOCKS + UDP DNS over SOCKS                                                                                                                             |
| `scripts/wsl-test.sh`               | Local smoke (plain / PSK) on WSL                                                                                                                               |
| `scripts/wsl-secure-boring-test.sh` | WSL: `cargo test -p bibavpn --features boring-tls`, release build, then **rustls+pin**, **boring+pin**, and **boring+insecure** smokes (openssl temp cert; strong token/PSK) |
| `scripts/wsl-proto-v3-smoke.sh`     | WSL: local SOCKS + `curl` smoke (release binaries + `openssl`, `python3`, `fuser`; script name is legacy)                                                      |
| `scripts/wsl-local-bench.sh`        | 64 MiB HTTP direct vs SOCKS+WSS throughput (run in WSL from repo root)                                                                                         |
| `scripts/wsl-udp-socks-bench.sh`    | SOCKS UDP throughput bench on WSL                                                                                                                              |
| `scripts/remote-deploy.sh`          | Sync + build + `Dockerfile.server.binary` deploy                                                                                                               |
| `scripts/remote-install-server.sh`  | Build the server image and `docker save` it                                                                                                                    |
| `scripts/speedtest-via-socks.py`    | Speedtest via SOCKS                                                                                                                                            |
| `scripts/run-remote-speedtest.sh`   | SSH + `speedtest-cli` on the VPS                                                                                                                               |
| `scripts/bibavpn_e2e.py`            | End-to-end test harness (Python)                                                                                                                               |
| `scripts/bibavpn_public_probe.py`   | Probe a public endpoint for basic reachability                                                                                                                 |
| `scripts/wsl-pcap-*.py`             | Packet-capture / DPI behavior labs (see the individual headers)                                                                                                |


**Remote client in Docker:** build `docker/Dockerfile.client`, then
`docker run` with published SOCKS/HTTP proxy ports; use `0.0.0.0` binds
inside the container.

## UDP design note (agents)

The server keeps a **pending map** (by destination `SocketAddr`) to correlate
`UDP_REP` to `UDP_REQ`. Under many concurrent requests to the same
`IP:port`, ordering assumptions matter (`xid` is per datagram). The client
**bumps `xid`** on collisions and may retry the SOCKS path so replies cannot be
attributed to the wrong request.

**DNS / multi-homed names:** `resolve_udp_dest` returns multiple resolved
addresses; the client tries them in order until one accepts.

**Server socket reuse:** optional **`--udp-socket-pool-size`** (see
[Server limits](#server-limits-hardening)) reuses a bounded set of UDP sockets
on the mux bridge instead of binding per datagram.

## Testing and benchmarks

**Обязательно после изменений в сервере или клиенте:** любые правки в
`bibavpn-server`, `bibavpn-client`, или модулях туннеля (`crypto_layer.rs`,
`protocol.rs`, `tcp_mux.rs`, `udp_mux.rs`, `local_client.rs`, `incoming.rs`,
`ws_auth.rs`, `stealth*.rs`, `frame.rs`, …) должны сопровождаться прогоном
тестов crate `bibavpn`:

```bash
cargo test -p bibavpn
cargo clippy -p bibavpn -- -D warnings   # рекомендуется перед PR
```

На Windows без MSVC linker удобнее WSL: `wsl bash -lc 'cd /mnt/c/.../biba-vpn && cargo test -p bibavpn'`.

После изменений wire-format / handshake дополнительно:

- `bash scripts/wsl-proto-v3-smoke.sh` — локальный SOCKS + smoke (proto 3)
- `bash scripts/docker-smoke.sh` — compose e2e (TLS+WSS)
- при правках UDP: `bash scripts/udp-socks-smoke.sh`
- при правках Boring: `bash scripts/wsl-secure-boring-test.sh`

Интеграционные тесты лежат в `bibavpn/tests/` (`smoke.rs`, `tunnel_integration.rs`,
`reality_handshake.rs`); юнит-тесты — рядом с кодом в `bibavpn/src/**` (`#[cfg(test)]`).

- Unit and integration tests live alongside the code in `bibavpn/src/…` and
  `bibavpn/tests/`. Run the whole workspace with:
  ```bash
  cargo test --workspace
  ```
- `scripts/docker-smoke.sh` is the cheapest end-to-end check that nothing
regressed at the TLS+WSS layer.
- `scripts/wsl-proto-v3-smoke.sh` is a quick local handshake + SOCKS check on
release binaries — run it after changes to `crypto_layer.rs`, `protocol.rs`,
or invite / CLI defaults.
- `scripts/wsl-secure-boring-test.sh` runs **unit tests with `boring-tls`**, then
  integration smokes: **rustls** + `--pin-cert`, **Boring** + `--pin-cert`, and
  **Boring** + `--insecure` (lab). Requires **WSL**, **OpenSSL**, **curl**; run from
  repo root: `bash scripts/wsl-secure-boring-test.sh`.
- After REALITY changes: `cargo test -p bibavpn --test reality_handshake`.
- `scripts/wsl-local-bench.sh` is a quick sanity check for throughput after  
changes to `frame.rs`, `tcp_mux.rs`, or `ws_bridge.rs`.

## Security

- **Do not commit:** `server.txt`, `.env`, passwords, PEM keys (see
`.gitignore`).
- Treat PSK, token, and invite passphrase as **secrets**.
- `--pin-cert` narrows trust; do not combine with `--insecure` on the
client. **BoringSSL** (`--tls-stack boring`) supports `--pin-cert` when built with `boring-tls`.
- Prefer **SSH keys** for `remote-deploy.sh`.
- Do not embed real credentials in docs or examples.

See **[SECURITY.md](SECURITY.md)** for the disclosure policy.

## Stealth, DPI, and roadmap

**Long-term targets:** [roadmap section in PROTOCOL.md](PROTOCOL.md#target-specification-roadmap).
**Release history:** [CHANGELOG.md](CHANGELOG.md).

This table tracks **PROTOCOL.md roadmap** items against what the **current tree**
(proto-3 wire + stealth layers) already ships, so new work does not duplicate effort.


| Area                     | In the tree today                                                                                                                                                    | Still target / gaps (see PROTOCOL)                                                   |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------ |
| **TLS / fingerprint**    | `TlsClientProfile` labels; `--fingerprint` + `client_policy` merge; **Boring** behind `--features boring-tls` + `--tls-stack boring`; **`--pin-cert` on Boring** (leaf DER match); `rustls` default                   | Full GREASE / extension-order parity; HTTP/2 transport |
| **Record fragmentation** | Client `--tls-fragment` — **Boring** enforces via `SSL_CTX_set_max_send_fragment` (`tls_boring.rs`); **rustls** logs “not implemented” (`desync::note_tls_fragment_requested`) | Full CH + app-data split on both stacks if required                                  |
| **RTT**                  | Server delayed ACK, `--rtt-mask-jitter-ms`, `--ack-profile` defaults; **1–4 WSS** + `TcpMuxSessionPool` RR (including REALITY)                                           | Broader “cross-layer” story + CI zapret/pcap (see spec)                              |
| **Padding**              | `PadMode::Adaptive` + `stealth` / presets                                                                                                                                | Future spec may redefine burst heuristics / budgets                                                                                      |
| **Jitter**               | Min/max MS on WS sends; preset merge                                                                                                                                     | Spec band (e.g. 5–25 ms) as product default                                          |
| **Decoys**               | Parallel `--decoy-gets` + idle decoys (`--idle-decoy-secs`): same **TLS/WS fingerprint class** as tunnel (UA / `Accept-Language` / upgrade shape); decoy fields in presets (`stealth_v12.rs`) | Full `--decoy-mode browser` catalog (Referer parity, etc.) per spec                     |
| **REALITY (WSS)**        | X25519 after WSS upgrade; pinned server pubkey in invite; **mandatory client AUTH MAC (token)** before any application frame; auto **SNI** from `reality_target`; plaintext mux; SpiderX; **rustls** or **boring** outer TLS; test `reality_handshake.rs` | Xray TLS ClientHello relay / uTLS parity on REALITY path |
| **Desync**               | `DesyncConfig` on wire + `desync` module (`effective_desync_mode` / `DesyncApplied`; operator notes in PROTOCOL/README) | Raw-socket / OS hook paths; privilege guards                                         |
| **UI / JNI**             | `start_json_config` fields for new options where wired                                                                                                                   | Expose all toggles in Tauri + Android as they stabilize                              |


**Testing:** keep unit tests beside each subsystem; for throughput, compare
`scripts/wsl-local-bench.sh` (or equivalent) to a saved baseline — **≤ ~10%**
regression target vs [PROTOCOL.md](PROTOCOL.md) acceptance.

**Stealth ≠ legal bypass:** document jurisdiction; do not ship defaults that
require root without explicit opt-in.

---

## Logging (tracing)

- **Targets:** use explicit `tracing` targets so operators can filter without guessing crate paths:
  `bibavpn_server`, `bibavpn_client`, `bibavpn_security` (auth / abuse),
  `bibavpn_stealth` (advisory transport / DPI hints), `bibavpn_mux`, `bibavpn_udp`,
  `bibavpn_camouflage`. The server emits **spans** around accepted sessions and
  hot paths (mux / UDP) so `tracing` tree views stay navigable.
- **Fields:** prefer structured fields (`session_id`, `peer_ip`, stream ids, errno summaries).
  **Never** log secrets: PSKs, tokens, passphrases, full invites, or PEM bodies.
- **Levels:** `info` for lifecycle and capacity summaries, `warn` for abuse / stealth mismatches,
  `debug` for high-volume operational detail. Use `log_ratelimit` helpers where a
  loop would otherwise spam logs.
- **CLI / JSON:** server and binary client accept `--log-level` and `--log-format plain|json`.
  The server may also pass `--log-filter` to supply a full `EnvFilter` directive
  (wins over `--log-level` when set — see `logging::init`).
- **Android / JSON start** (`start_json_config`): optional `log_level` and `log_format`; JNI
  initializes tracing once per process (duplicate init is ignored; JSON start does not yet mirror `--log-filter`).

---

## Guidelines for agents

1. Touch only what the task needs; avoid unrelated refactors.
2. Match existing style (`clap`, `tracing`, async, imports); new subsystems
   should log under an existing **`bibavpn_*`** target or add a narrowly scoped
   one documented above — never uncategorised root logging for hot paths.
3. Any wire-format change: update client **and** server plus tests; keep
  **[PROTOCOL.md](PROTOCOL.md)** in sync for on-wire layouts, and mirror
   the user-facing description into **[README.md](README.md)** if it
   affects the CLI.
4. **После правок server/client или модулей туннеля — всегда `cargo test -p bibavpn`**
   (см. [Testing and benchmarks](#testing-and-benchmarks)); добавляй или обновляй
   тесты в том же PR. После Docker / Compose edits, run `scripts/docker-smoke.sh`;
   after UDP changes, `scripts/udp-socks-smoke.sh`; for throughput sanity,
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
- WSL handshake smoke (`scripts/wsl-proto-v3-smoke.sh`): release server/client, SOCKS
`curl` over localhost.
- Speedtest via SOCKS (`scripts/speedtest-via-socks.py` in a venv).
- Server/client images and slim remote image via
`docker/Dockerfile.server.binary`.

---

## Learned User Preferences

- User often writes in Russian; match that language in replies when they do.
- When executing an attached plan: do not edit the plan file; use pre-created todos, mark them in_progress, and finish all of them.
- Split git changes into separate logical commits with English messages; never mention Cursor or other AI tooling in commit text.
- Do not commit `experiments/` (local lab/DPI work; already in `.gitignore`).
- Prefer end-to-end autonomous ops (build, deploy, smoke-test, return `biba://` + passphrase) over leaving partial scripts for the user.
- CI should run only when relevant paths change (protocol, server, apps), not on every commit.
- Unified Tauri UI across Windows, Android, and macOS: dark theme only, multi-profile, logs hidden from the front-end; follow `united-design-new/` for layout.
- Android debug CI artifacts should include only the Android APK, not bundles for other platforms.

## Learned Workspace Facts

- Monorepo root is `biba-vpn/`; Rust VPN stack in `biba-vpn/biba-vpn/`; control plane in `biba-vpn/biba-control-plane/`. Root `.cursorrules` routes Python/control-plane work to `biba-control-plane/AGENTS.md` and `make ci`.
- On the Windows dev machine, WSL Ubuntu is the primary path for `cargo test`, Docker compose, Android builds (NDK/adb), and SSH-based VPS deploys (RSA keys live in WSL).
- Split-tunnel bypass domain lists are fetched from the control-plane public API; apps use `BIBA_BYPASS_DOMAINS_URL` at build/runtime (CI secret or local `.env`), not a hardcoded URL in the open repo.
- User-facing docs should describe proto 3 only; avoid legacy v1/v2 hello/wire references that confuse readers.
- Local DPI/fingerprint proof labs belong under gitignored `experiments/`; scope tests to owned infrastructure only.

---

*For humans and AI agents working on the BibaVPN repository.*