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

**Quick start**

```bash
git clone https://github.com/Eljaja/BibaVPN
cd BibaVPN
bash start.sh
#Download app from releases
```

([Releases](https://github.com/Eljaja/BibaVPN/releases) — Android & desktop. `bash start.sh` prints a labeled **Invite URI** (`biba://…`) and **Passphrase**; paste both into the app.)

- **Docs**
  - [docs/manual/](docs/manual/) — **English user manual** (how it works, download, server & client setup) for websites
  - [PROTOCOL.md](PROTOCOL.md) — wire formats, session flow, invite URI, **BibaV4 roadmap** + **v3 + implementation status**
  - [AGENTS.md](AGENTS.md) — architecture, CLI flags, deploy notes, scripts, **stealth vs BibaV4**
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
- Many logical streams are multiplexed over **one to four** outer WebSocket
**sessions** (client `--ws-parallel`, round-robin stream placement) or **one**
when `ws_parallel=1` — trading extra handshakes for more natural parallelism.

For the full wire format, frame layout and session setup see
**[PROTOCOL.md](PROTOCOL.md)**.

---

## Features

- **SOCKS5** (TCP CONNECT + UDP ASSOCIATE) and **HTTP CONNECT** on the client.
- **TLS + WebSocket** transport; the server serves plain HTTP on the same port
as camouflage (`--camouflage-dir` for a static site, `--camouflage-url` for a
reverse origin).
- **Biba** shared-PSK wire: variable-length opaque HELLO/ACK (no fixed
33/48-byte signatures), **domain-separated** key derivation (`--proto-domain`),
and **sealed** control frames (AUTH, OPEN, MUX / UDP_MUX, OPEN_OK / OPEN_ERR).
UDP datagrams use **v3 single-byte opcodes** (`0x05` / `0x06` for REQ/REP) inside
the AEAD plaintext, not legacy ASCII magics.
- **Biba** shaping knobs: **adaptive** / random / HTTP-bucket padding, WS
Ping with jitter, binary size cap, **per-frame WS jitter (min–max ms)**,
configurable upgrade headers per **TLS client profile** (default **Chrome
132+** when nothing else is selected), early-session noise, **TLS** via **rustls**
(default) or **BoringSSL** (`--features boring-tls`, client `--tls-stack boring`;
**`--pin-cert`** on both stacks), TLS leaf pinning (`--pin-cert`).
- **REALITY (WSS):** optional front-domain mode — TLS **SNI** from `reality_target`,
  X25519 proof-of-server after WebSocket upgrade, then plaintext TCP mux (see
  [PROTOCOL.md — REALITY](PROTOCOL.md#reality-wss-path)).
- **TCP mux** over **1–4** outer WSS sessions (round-robin when `--ws-parallel` is
2–4) + a separate **single** WSS for UDP mux.
- **Biba extras:** optional `--stealth-profile`, `fingerprint` / `tls_profile`
merge rules (`client_policy`), parallel decoys plus **idle** decoys, server
**delayed ACK** + **ACK profile** and RTT mask — see [AGENTS.md](AGENTS.md).
- **Packet desync / TCP “fooling” flags** in the client are **mostly advisory** in the default build; real DPI-oriented split/disorder usually means an **external** helper (e.g. **zapret**-class tools) documented in [PROTOCOL.md](PROTOCOL.md) (external desync section).
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


| Crate                            | Role                                                                       |
| -------------------------------- | -------------------------------------------------------------------------- |
| `bibavpn`                        | `lib` + binaries `bibavpn-server`, `bibavpn-client`, `bibavpn-mint-invite` |
| `biba`                           | uTLS-like TLS fingerprint helpers                                          |
| `apps/bibavpn-jni`               | Android JNI glue around `bibavpn` (crate name `bibavpn-jni`)               |
| `apps/bibavpn-desktop/src-tauri` | Tauri desktop wrapper (systray, platform proxy setup)                      |


Common commands:

```bash
cargo build --release -p bibavpn --bin bibavpn-server
cargo build --release -p bibavpn --bin bibavpn-client
cargo test --workspace
```

**BoringSSL client path** (optional; needs `cmake` / `nasm` on some platforms):

```bash
cargo build --release -p bibavpn --features boring-tls --bin bibavpn-client
cargo test -p bibavpn --features boring-tls
bash scripts/wsl-secure-boring-test.sh   # WSL: pin + boring integration smokes
```

Use `--tls-stack boring` on the client. **`--pin-cert`** is supported on both rustls and boring.

A `rust-toolchain.toml` pins the compiler version so CI and local builds stay
reproducible. Docker images use the same or a newer toolchain.

---

## v1.2.0 — BibaV4 breaking changes

The **1.2.x** line ships **Biba v3** on the wire today and implements many
**BibaV1.2** anti-DPI behaviors as optional layers. The long-term **BibaV4**
product spec in [PROTOCOL.md](PROTOCOL.md#bibav4-v120-target-specification) may
still **replace** inner opcodes or KDF/invite fields — that would be a true
**breaking** wire change. Until such a cutover, treat releases as “**v3 + stealth**”
and keep **client, server, and app builds** on the same version line.

[PROTOCOL — Implementation status](PROTOCOL.md#implementation-status-12x-on-v3)
lists what is already in code versus what remains **roadmap** relative to the
BibaV4 bullet list. Always follow [SECURITY.md](SECURITY.md) and local law.

---

## Comparison (at a glance)

Rough positioning only; details depend on version and network path. Stealth
features land incrementally on top of v3; check the crate version and
[CHANGELOG.md](CHANGELOG.md).


|                       | **BibaVPN (1.2.x, v3 wire)**                     | [wstunnel](https://github.com/erebe/wstunnel) | [Hysteria2](https://v2.hysteria.network/) | **REALITY** (e.g. Xray)       |
| --------------------- | ------------------------------------------------ | --------------------------------------------- | ----------------------------------------- | ----------------------------- |
| **Primary transport** | TLS + WSS, PSK inner                             | TLS + WSS, generic                            | QUIC                                      | TLS fronting / proxy protocol |
| **DPI focus**         | Explicit (fingerprints, timing, padding, decoys, WSS REALITY) | General tunneling                             | Brutal throughput / quic                  | Site mimicry (TLS hook)       |
| **Typical role**      | Single small VPS, SOCKS/CONNECT                  | Port forwarding / WSS                         | High perf                                 | Domain / cert fronting style  |
| **Ecosystem**         | Rust + mobile/desktop in-repo                    | many                                          | Go server                                 | V2Ray / Xray family           |


BibaVPN does not claim a security or anonymity property beyond “harder to
classify on the wire” — see [Security](#security).

---

## Configuration

Every CLI flag is documented in **[AGENTS.md](AGENTS.md)**. The short story:

- **Required for an encrypted tunnel:** `--server`, `--sni`, `--token`, `--psk`.
The client wire is **Biba v3 only** (`--proto` defaults to `**3`**). Server
`--proto-domain` (default `default`) must match the client’s `--proto-domain`, or
the **SNI** when the client leaves `--proto-domain` empty.
- **Shape / anti-DPI:** `--decoy-max`, `--max-pad`, `--pad-mode`,
`--dummy-interval-secs`, `--ws-ping-secs`, `--junk-frames`,
`--stealth-profile`, `--fingerprint` / effective TLS client profile, `--ws-jitter-min-ms` /
`--ws-jitter-max-ms`, `--ws-parallel`, `--decoy-gets`*, `--idle-decoy-secs`
(client), `--tls-stack` (with `boring-tls` build if needed), `--tls-fragment`.
- **Server timing:** `--ack-profile`, `--server-ack-delay-*-ms`, `--rtt-mask-jitter-ms`
(see [AGENTS.md](AGENTS.md) for when profiles apply).
- **Camouflage on the TLS port (server):** `--camouflage-dir <path>` or
`--camouflage-url http://…`.
- **TLS trust (client):** real CA by default, `--pin-cert <pem>` to pin the
leaf on **rustls or boring**, `--insecure` **lab only**.
- **REALITY (optional):** server `--reality-target`, `--reality-private-key`;
  client / invite `reality_target`, `reality_public_key`, `reality_short_id`.
  When REALITY is on, outer **SNI** defaults to the front host from `reality_target`
  (e.g. `vk.com:443` → SNI `vk.com`); TCP still connects to your VPS `--server` address.

Never put secrets in the URL: the token is carried in the **v3 sealed AUTH**
opcode after HELLO/ACK, and the WebSocket path (`--ws-path`, default `/ws`) does
not contain credentials.

**Invites:** JSON includes `**proto`** (default `**3**`) and optional
`**proto_domain**` (see **[PROTOCOL.md](PROTOCOL.md)**). `**--print-invite-uri`**
and `**bibavpn-mint-invite**` both target v3 by default.

**WSL smoke:** after `cargo build --release -p bibavpn`, you can run
`scripts/wsl-proto-v3-smoke.sh` for a quick local SOCKS + `curl` check (see
**AGENTS.md**).

---

## Android and desktop

- **Android + desktop (Tauri):** `apps/bibavpn-desktop/` (Vite UI + Tauri shell).
Android VPN glue lives under `src-tauri/android-bibavpn-extras/` and is merged
into Tauri's generated Android project by `apps/scripts/integrate-bibavpn-into-tauri-android.sh`.
Prebuilt binaries are emitted by the GitHub Actions workflows in `.github/workflows/`.

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