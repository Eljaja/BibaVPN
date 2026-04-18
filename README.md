# BibaVPN

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Docker Hub — server](https://img.shields.io/docker/pulls/eljaja/bibavpn-server?label=docker%20server)](https://hub.docker.com/r/eljaja/bibavpn-server)
[![Docker Hub — client](https://img.shields.io/docker/pulls/eljaja/bibavpn-client?label=docker%20client)](https://hub.docker.com/r/eljaja/bibavpn-client)

A DPI-resistant **SOCKS5 / HTTP-CONNECT** tunnel that wraps your traffic in
**TLS + WebSocket** and ships it through a single VPS. Optional shared-PSK
layer (**BibaV2**), per-frame random padding, browser-ordered upgrade headers,
and HTTP camouflage on the same TLS port.

Pure Rust server and client; Android app (Jetpack Compose) and a Tauri desktop
wrapper live in the same workspace.

> **Status:** experimental. Protocol is not frozen — treat any deployment as a
> personal lab, not a production service. See [Security](#security).

- **Docs**
  - [PROTOCOL.md](PROTOCOL.md) — wire formats, session flow, invite URI
  - [AGENTS.md](AGENTS.md) — architecture, CLI flags, deploy notes, scripts
  - [DESIGN.md](DESIGN.md) — brand / UI design system for ports

---

## Contents

- [What it does](#what-it-does)
- [Features](#features)
- [Quick start](#quick-start)
  - [A. One-liner from Docker Hub](#a-one-liner-from-docker-hub)
  - [B. Local lab, built from source (docker compose)](#b-local-lab-built-from-source-docker-compose)
  - [C. Real VPS + client from source](#c-real-vps--client-from-source)
  - [D. Client against an existing server](#d-client-against-an-existing-server)
  - [E. Encrypted `biba://` invite](#e-encrypted-biba-invite)
- [Using the tunnel](#using-the-tunnel)
- [Build from source](#build-from-source)
- [Configuration](#configuration)
- [Android and desktop](#android-and-desktop)
- [Security](#security)
- [License](#license)

---

## What it does

```
┌─────────┐   SOCKS5 /     ┌───────────────┐   TLS + WSS    ┌───────────────┐   TCP/UDP   ┌────────┐
│  apps   │ ─HTTP CONNECT─►│ bibavpn-client│ ─────────────► │ bibavpn-server│ ──────────► │ target │
└─────────┘   (plaintext)  └───────────────┘  one socket    └───────────────┘             └────────┘
                                              (mux)
```

- **Client** runs on your machine and exposes a local **SOCKS5** (and optional
  HTTP CONNECT) endpoint.
- **Server** runs on a VPS, terminates TLS + WebSocket, and dials the target
  TCP / UDP destination.
- Many logical streams are multiplexed over **one** persistent WebSocket —
  fewer TLS handshakes, less distinctive traffic shape.

For the full wire format, frame layout and session setup see
**[PROTOCOL.md](PROTOCOL.md)**.

---

## Features

- **SOCKS5** (TCP CONNECT + UDP ASSOCIATE) and **HTTP CONNECT** on the client.
- **TLS + WebSocket** transport; the server serves plain HTTP on the same port
  as camouflage (`--camouflage-dir` for a static site, `--camouflage-url` for a
  reverse origin).
- **BibaV2** shared-PSK layer: HELLO / ACK, ChaCha20-Poly1305 AEAD, per-frame
  random decoy.
- **BibaV2.1** shaping knobs: random / HTTP-bucket padding, WS Ping with
  jitter, binary size cap, configurable upgrade headers per TLS profile
  (Chrome / Firefox), early-session noise, TLS leaf pinning (`--pin-cert`).
- **TCP mux** over one WSS (stream open / data / window / close) + a separate
  UDP mux.
- **Encrypted invite URIs** (`biba://…`) so you can ship one line of config
  instead of a wall of flags.
- **Android** app (Jetpack Compose, JNI core) and **Tauri desktop** wrapper.

---

## Quick start

You will need **Docker** (for the image-based paths) or **Rust 1.78+** (the
repo pins a toolchain in `rust-toolchain.toml`) if you want to build from
source. For anything beyond a local lab you also need a spare **VPS or LAN
host** to act as the server.

### A. One-liner from Docker Hub

Prebuilt multi-arch (`linux/amd64`, `linux/arm64`) images live on Docker Hub:

- [`eljaja/bibavpn-server`](https://hub.docker.com/r/eljaja/bibavpn-server)
- [`eljaja/bibavpn-client`](https://hub.docker.com/r/eljaja/bibavpn-client)

The repo ships a ready-made compose file that pulls both images, wires them
on one Docker network, and exposes the client's SOCKS5 on `localhost:11080`
and HTTP CONNECT on `localhost:11880`:

```bash
# pull + run (no build step)
curl -fsSL https://raw.githubusercontent.com/Eljaja/BibaVPN/main/docker-compose.hub.yml \
  -o docker-compose.hub.yml

# pick your own secrets (both sides must agree)
export BIBA_VPN_TOKEN="$(openssl rand -hex 16)"
export BIBA_VPN_PSK="$(openssl rand -hex 32)"

docker compose -f docker-compose.hub.yml up -d
# SOCKS5:  127.0.0.1:11080
# HTTP:    127.0.0.1:11880
```

Or, if you've already cloned the repo:

```bash
BIBA_VPN_TOKEN=$(openssl rand -hex 16) \
BIBA_VPN_PSK=$(openssl rand -hex 32) \
docker compose -f docker-compose.hub.yml up -d
```

Smoke test:

```bash
curl --socks5-hostname 127.0.0.1:11080 https://ifconfig.io
curl -x http://127.0.0.1:11880 https://ifconfig.io
```

> This variant uses a **self-signed** cert inside the Docker network and the
> client runs with `--insecure`. That is fine for a localhost lab, *not* for
> a real VPN. For that, see [C](#c-real-vps--client-from-source).

Image tags:

| Tag            | Meaning                                              |
| -------------- | ---------------------------------------------------- |
| `:latest`      | HEAD of `main` (CI publishes on every push).         |
| `:vX.Y.Z`      | Pinned release. Prefer this for anything long-lived. |
| `:sha-abc1234` | Exact commit. Useful for rollback.                   |

### B. Local lab, built from source (docker compose)

Same layout as [A](#a-one-liner-from-docker-hub) but builds both images
locally from this checkout — useful when hacking on the code:

```bash
docker compose up --build
```

Or the one-shot script (build + curl + teardown):

```bash
./scripts/docker-smoke.sh
```

### C. Real VPS + client from source

1. **Build both binaries locally** (Linux or WSL):

   ```bash
   cargo build --release -p bibavpn --bin bibavpn-server
   cargo build --release -p bibavpn --bin bibavpn-client
   ```

2. **Pick your secrets** and put them in your shell (do *not* commit):

   ```bash
   export BIBA_VPN_TOKEN="$(openssl rand -hex 16)"
   export BIBA_VPN_PSK="$(openssl rand -hex 32)"
   export BIBA_HOST="vpn.example.com"   # or IP
   ```

3. **Start the server** on the VPS (here: self-signed TLS for a quick lab —
   for production use real certs, see [Security](#security)):

   ```bash
   ./target/release/bibavpn-server \
     --listen 0.0.0.0:8443 \
     --self-signed-san "$BIBA_HOST" \
     --token "$BIBA_VPN_TOKEN" \
     --psk "$BIBA_VPN_PSK" \
     --decoy-max 32 --max-pad 64 \
     --max-ws-binary 262144 --ws-ping-secs 25
   ```

4. **Start the client** locally, pointing at the VPS:

   ```bash
   ./target/release/bibavpn-client \
     --server "$BIBA_HOST:8443" --sni "$BIBA_HOST" \
     --token "$BIBA_VPN_TOKEN" --psk "$BIBA_VPN_PSK" \
     --decoy-max 32 --max-pad 64 \
     --max-ws-binary 262144 --ws-ping-secs 25 \
     --insecure \
     --socks5 127.0.0.1:1080
   ```

   `--insecure` disables cert verification and is **lab-only**. Remove it
   together with `--self-signed-san` once you have a real certificate or
   switch to `--pin-cert <leaf.pem>`.

### D. Client against an existing server

If somebody else is already running a BibaVPN server and shared `host`,
`token`, `psk` (and optionally a TLS pin) with you out of band:

```bash
./target/release/bibavpn-client \
  --server "$HOST:8443" --sni "$HOST" \
  --token "$TOKEN" --psk "$PSK" \
  --pin-cert server-leaf.pem \
  --socks5 127.0.0.1:1080
```

### E. Encrypted `biba://` invite

Instead of juggling flags, the server can emit a one-line encrypted config
and the client can consume it:

```bash
# server (prints exactly one biba://… line to stdout after bind)
./target/release/bibavpn-server … \
  --print-invite-uri \
  --invite-passphrase "$BIBA_INVITE_PASSPHRASE" \
  --invite-public "$BIBA_HOST:8443" \
  --invite-sni "$BIBA_HOST"

# client (mutually exclusive with --server / --token)
./target/release/bibavpn-client \
  --from-invite 'biba://…' \
  --invite-passphrase "$BIBA_INVITE_PASSPHRASE" \
  --socks5 127.0.0.1:1080
```

Share the passphrase out-of-band, never in the same channel as the URI. See
[PROTOCOL.md#encrypted-invite-biba](PROTOCOL.md#encrypted-invite-biba).

---

## Using the tunnel

Once the client is up, point your apps at the local SOCKS5 / HTTP CONNECT:

- **Browser (Firefox)**: *Settings → Network → Manual proxy*,
  SOCKS5 host `127.0.0.1`, port `1080`, "Proxy DNS when using SOCKS v5" **on**.
- **Browser (Chrome / Chromium)**:
  `--proxy-server="socks5://127.0.0.1:1080"`.
- **curl**: `curl --socks5-hostname 127.0.0.1:1080 https://…`.
- **System-wide on Linux**: use `proxychains` or set `ALL_PROXY=socks5h://127.0.0.1:1080`.

---

## Build from source

Workspace layout (cargo workspace):

| Crate | Role |
| ----- | ---- |
| `bibavpn` | `lib` + binaries `bibavpn-server`, `bibavpn-client`, `bibavpn-mint-invite` |
| `biba` | uTLS-like TLS fingerprint helpers |
| `bibavpn-jni` | Android JNI glue around `bibavpn` |
| `bibavpn-desktop/src-tauri` | Tauri desktop wrapper (systray, platform proxy setup) |

Common commands:

```bash
cargo build --release -p bibavpn --bin bibavpn-server
cargo build --release -p bibavpn --bin bibavpn-client
cargo test --workspace
```

A `rust-toolchain.toml` pins the compiler version so CI and local builds stay
reproducible. Docker images use the same or a newer toolchain.

---

## Configuration

Every CLI flag is documented in **[AGENTS.md](AGENTS.md)**. The short story:

- **Required for an encrypted tunnel:** `--server`, `--sni`, `--token`, `--psk`.
- **Shape / anti-DPI:** `--decoy-max`, `--max-pad`, `--pad-mode`,
  `--dummy-interval-secs`, `--ws-ping-secs`, `--junk-frames`,
  `--decoy-gets*` (client-only).
- **Camouflage on the TLS port (server):** `--camouflage-dir <path>` or
  `--camouflage-url http://…`.
- **TLS trust (client):** real CA by default, `--pin-cert <pem>` to pin the
  leaf, `--insecure` **lab only**.

Never put secrets in the URL: the token is carried in the `AUTH` binary
frame, and the WebSocket path (`--ws-path`, default `/ws`) does not
contain credentials.

---

## Android and desktop

- **Android:** `android/` (Jetpack Compose + `BibaVpnService`). Build the JNI
  core with `scripts/wsl-build-all.sh`, then open the `android/` project in
  Android Studio.
- **Desktop (Tauri):** `bibavpn-desktop/` (Vite UI + Tauri shell). Prebuilt
  binaries are emitted by the GitHub Actions workflows in `.github/workflows/`
  for Windows and macOS.

See [DESIGN.md](DESIGN.md) for the shared visual language if you want to port
the UI elsewhere.

---

## Security

BibaVPN is an **experimental tunnel**, not a hardened product. Known caveats:

- **Secrets in the repo:** `PSK`, `token` and any `invite-passphrase` must
  stay out of git. The repo ships an `.gitignore` that covers `server.txt`,
  `.env*`, `*.pem`, `*.key` and related local files. **Do not commit real
  credentials. Rotate anything that ever leaked.**
- **`--insecure` is lab-only.** For anything you actually care about, use a
  real certificate (e.g. Let's Encrypt via a reverse proxy) or pin the leaf
  with `--pin-cert`.
- **Threat model:** BibaVPN aims to make the outer flow *look like* a
  long-lived HTTPS WebSocket to a reasonable camouflage site. It is not
  anonymity software; the server operator sees every byte you send, and
  active probing with the right keys recovers the inner protocol.
- **Token path:** `--legacy-path-auth` accepts an old `/b/{token}` URL
  form without the AUTH frame. It is only there for old clients and is
  strictly weaker than the default.
- **Report security issues** privately — see [SECURITY.md](SECURITY.md).

---

## License

MIT — see [LICENSE](LICENSE). Third-party crates retain their own licenses
(`cargo tree --duplicates`, `cargo about` if you want a full inventory).
