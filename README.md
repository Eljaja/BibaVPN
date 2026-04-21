# BibaVPN

[GitHub release](https://github.com/Eljaja/BibaVPN/releases)
[License: MIT](LICENSE)
[Rust](https://www.rust-lang.org/)
[Docker](https://www.docker.com/)
[Platforms](#android-and-desktop)

A DPI-resistant **SOCKS5 / HTTP-CONNECT** tunnel that wraps your traffic in
**TLS + WebSocket** and ships it through a single VPS. The inner wire uses the
**Biba v3** shared-PSK layer (opaque HELLO/ACK, ChaCha20-Poly1305, per-frame
random decoy), plus per-frame random padding, browser-ordered upgrade headers,
and HTTP camouflage on the same TLS port.

Pure Rust server and client; Android app (Jetpack Compose) and a Tauri desktop
wrapper live in the same workspace.

> **Status:** experimental. Protocol is not frozen — treat any deployment as a
> personal lab, not a production service. See [Security](#security).

> **v1.2.0 (branch) — breaking / BibaV4:** this line targets a **full DPI-hardening
> redesign** (handshake, framing, padding, TLS fingerprinting, optional
> desync / timing masks). It is **not** wire-compatible with older Biba v3
> servers or clients. See [BibaV4 section below](#v120--bibav4-breaking-changes),
> [PROTOCOL.md](PROTOCOL.md#bibav4-v120-target-specification), and
> [CHANGELOG.md](CHANGELOG.md).

**Quick start**

```bash
git clone https://github.com/Eljaja/BibaVPN
cd BibaVPN
bash start.sh
#Download app from releases
```

([Releases](https://github.com/Eljaja/BibaVPN/releases) — Android & desktop. `bash start.sh` prints a labeled **Invite URI** (`biba://…`) and **Passphrase**; paste both into the app.)

- **Docs**
  - [PROTOCOL.md](PROTOCOL.md) — wire formats, session flow, invite URI, **BibaV4 target spec**
  - [AGENTS.md](AGENTS.md) — architecture, CLI flags, deploy notes, scripts, **stealth checklist**
  - [CHANGELOG.md](CHANGELOG.md) — v1.2.0 / BibaV4 release notes
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
- [v1.2.0 — BibaV4 breaking changes](#v120--bibav4-breaking-changes)
- [Comparison (at a glance)](#comparison-at-a-glance)
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
- **Biba v3** shared-PSK wire: variable-length opaque HELLO/ACK (no fixed
33/48-byte signatures), **domain-separated** key derivation (`--proto-domain`),
and **sealed** control frames (AUTH, OPEN, MUX / UDP_MUX, OPEN_OK / OPEN_ERR).
UDP datagrams use **v3 single-byte opcodes** (`0x05` / `0x06` for REQ/REP) inside
the AEAD plaintext, not legacy ASCII magics.
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

The snippet at the top of this file is enough for a local Docker lab; you need
**Docker** (e.g. Docker Desktop or WSL2 + Docker on Windows). First run:
`bash start.sh --build`. For a public server, set `BIBA_INVITE_PUBLIC` and
`BIBA_INVITE_SNI` before `bash start.sh`. Full invite / flag details:
[E. Encrypted `biba://` invite](#e-encrypted-biba-invite). Landing page:
[GitHub Pages](https://eljaja.github.io/BibaVPN/) (source: [docs/index.html](docs/index.html)).

### A. One-liner from Docker Hub

Prebuilt multi-arch (`linux/amd64`, `linux/arm64`) images live on Docker Hub:

- [eljaja/bibavpn-server](https://hub.docker.com/r/eljaja/bibavpn-server)
- [eljaja/bibavpn-client](https://hub.docker.com/r/eljaja/bibavpn-client)

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

To build the **server image from this checkout** and run it with the same
defaults as the quick path (including invite + `262144` WS cap), use:

```bash
bash start.sh --build
```

(`start.sh` writes `.biba-start.env` and runs `docker compose --env-file … up -d`.
Plain `docker compose up` without those variables will fail — see
`[docker-compose.yml](docker-compose.yml)`.)

For a **client + server** lab that pulls **prebuilt Hub images** instead, use
[A](#a-one-liner-from-docker-hub). For an automated build + curl smoke test

- teardown:

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


| Crate                       | Role                                                                       |
| --------------------------- | -------------------------------------------------------------------------- |
| `bibavpn`                   | `lib` + binaries `bibavpn-server`, `bibavpn-client`, `bibavpn-mint-invite` |
| `biba`                      | uTLS-like TLS fingerprint helpers                                          |
| `bibavpn-jni`               | Android JNI glue around `bibavpn`                                          |
| `bibavpn-desktop/src-tauri` | Tauri desktop wrapper (systray, platform proxy setup)                      |


Common commands:

```bash
cargo build --release -p bibavpn --bin bibavpn-server
cargo build --release -p bibavpn --bin bibavpn-client
cargo test --workspace
```

A `rust-toolchain.toml` pins the compiler version so CI and local builds stay
reproducible. Docker images use the same or a newer toolchain.

---

## v1.2.0 — BibaV4 breaking changes

The **`v1.2.0` git branch** and the **1.2.x** crate / app releases implement the
**BibaV4** DPI focus: single-VPS, Rust core, **TLS + WebSocket** transport,
**Android** + **Tauri** UIs, with **no obligation** to stay compatible with
Biba v3 wire or older apps. Operators should upgrade **client and server
together** and re-issue invites / configs.

Design goals (see [PROTOCOL.md](PROTOCOL.md#bibav4-v120-target-specification)) include
uTLS-class ClientHello control, cross-layer RTT mitigation, adaptive padding,
browser-like decoy sessions, and optional userspace desync — subject to
legitimate use and [SECURITY.md](SECURITY.md) cautions.

---

## Comparison (at a glance)

Rough positioning only; details depend on version and network path. BibaV4
features in this branch land incrementally; check the crate version and
[CHANGELOG.md](CHANGELOG.md).

| | **BibaVPN (v1.2.0 target)** | [wstunnel](https://github.com/erebe/wstunnel) | [Hysteria2](https://v2.hysteria.network/) | **REALITY** (e.g. Xray) |
| --- | --- | --- | --- | --- |
| **Primary transport** | TLS + WSS, PSK inner | TLS + WSS, generic | QUIC | TLS fronting / proxy protocol |
| **DPI focus** | Explicit (fingerprints, timing, padding, decoys) | General tunneling | Brutal throughput / quic | Site mimicry |
| **Typical role** | Single small VPS, SOCKS/CONNECT | Port forwarding / WSS | High perf | Domain fronting style |
| **Ecosystem** | Rust + mobile/desktop in-repo | many | Go server | V2Ray / Xray family |

BibaVPN does not claim a security or anonymity property beyond “harder to
classify on the wire” — see [Security](#security).

---

## Configuration

Every CLI flag is documented in **[AGENTS.md](AGENTS.md)**. The short story:

- **Required for an encrypted tunnel:** `--server`, `--sni`, `--token`, `--psk`.
The client wire is **Biba v3 only** (`--proto` defaults to **`3`**). Server
`--proto-domain` (default `default`) must match the client’s `--proto-domain`, or
the **SNI** when the client leaves `--proto-domain` empty.
- **Shape / anti-DPI:** `--decoy-max`, `--max-pad`, `--pad-mode`,
`--dummy-interval-secs`, `--ws-ping-secs`, `--junk-frames`,
`--decoy-gets`* (client-only).
- **Camouflage on the TLS port (server):** `--camouflage-dir <path>` or
`--camouflage-url http://…`.
- **TLS trust (client):** real CA by default, `--pin-cert <pem>` to pin the
leaf, `--insecure` **lab only**.

Never put secrets in the URL: the token is carried in the **v3 sealed AUTH**
opcode after HELLO/ACK, and the WebSocket path (`--ws-path`, default `/ws`) does
not contain credentials.

**Invites:** JSON includes **`proto`** (default **`3`**) and optional
**`proto_domain`** (see **[PROTOCOL.md](PROTOCOL.md)**). **`--print-invite-uri`**
and **`bibavpn-mint-invite`** both target v3 by default.

**WSL smoke:** after `cargo build --release -p bibavpn`, you can run
`scripts/wsl-proto-v3-smoke.sh` for a quick local SOCKS + `curl` check (see
**AGENTS.md**).

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
`.env`*, `*.pem`, `*.key` and related local files. **Do not commit real
credentials. Rotate anything that ever leaked.**
- `**--insecure` is lab-only.** For anything you actually care about, use a
real certificate (e.g. Let's Encrypt via a reverse proxy) or pin the leaf
with `--pin-cert`.
- **Threat model:** BibaVPN aims to make the outer flow *look like* a
long-lived HTTPS WebSocket to a reasonable camouflage site. It is not
anonymity software; the server operator sees every byte you send, and
active probing with the right keys recovers the inner protocol.
- **Token path:** `--legacy-path-auth` accepts an old `/b/{token}` URL
form without the sealed AUTH step. It is only there for old clients and is
strictly weaker than the default.
- **Report security issues** privately — see [SECURITY.md](SECURITY.md).

---

## License

MIT — see [LICENSE](LICENSE). Third-party crates retain their own licenses
(`cargo tree --duplicates`, `cargo about` if you want a full inventory).