# BibaVPN

[![Release](https://img.shields.io/github/v/release/Eljaja/BibaVPN?sort=semver)](https://github.com/Eljaja/BibaVPN/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-stable-orange.svg)](https://www.rust-lang.org/)
[![Docker](https://img.shields.io/badge/Docker-multi--arch-blue.svg)](https://hub.docker.com/r/eljaja/bibavpn-server)

A DPI-resistant **SOCKS5 / HTTP-CONNECT** tunnel that wraps your traffic in
**TLS + WebSocket** and ships it through a single VPS. Pure-Rust client and
server, plus an Android app (Jetpack Compose) and a Tauri desktop wrapper in the
same workspace.

**Highlights**

- **Encrypted inner wire:** opaque HELLO/ACK, ChaCha20-Poly1305, domain-separated
  keys, sealed control frames, per-frame random decoy + padding.
- **Looks like normal HTTPS:** browser-ordered upgrade headers, configurable TLS
  client profile (rustls default, optional BoringSSL), leaf pinning, HTTP
  camouflage on the same port.
- **Stream multiplexing** over 1–4 outer WSS sessions, plus a separate WSS for
  UDP relay.
- **Optional REALITY** front-domain mode and **encrypted `biba://` invites**
  (one line of config instead of a wall of flags).

> **Status: experimental.** The protocol is not frozen — treat any deployment as
> a personal lab, not a production service. See [Security](#security).

```
┌─────────┐   SOCKS5 /     ┌───────────────┐   TLS + WSS    ┌───────────────┐   TCP/UDP   ┌────────┐
│  apps   │ ─HTTP CONNECT─►│ bibavpn-client│ ─────────────► │ bibavpn-server│ ──────────► │ target │
└─────────┘   (plaintext)  └───────────────┘  one socket    └───────────────┘             └────────┘
                                              (mux)
```

The client exposes a local SOCKS5 (and optional HTTP CONNECT) endpoint; the
server terminates TLS + WebSocket on a VPS and dials the target. Full wire
format and session flow: **[PROTOCOL.md](PROTOCOL.md)**.

## Quick start

You need **Docker** (for the lab path) or **Rust stable** (pinned via
`rust-toolchain.toml`) to build from source. Anything beyond a local lab also
needs a VPS or LAN host for the server.

### A. Local Docker lab

```bash
git clone https://github.com/Eljaja/BibaVPN
cd BibaVPN
bash start.sh          # first run: bash start.sh --build
```

`start.sh` generates secrets, brings up the server via `docker compose`, and
prints a labeled **Invite URI** (`biba://…`) and **Passphrase** — paste both into
the app, or smoke-test from the shell:

```bash
curl --socks5-hostname 127.0.0.1:11080 https://ifconfig.io   # SOCKS5
curl -x http://127.0.0.1:11880          https://ifconfig.io   # HTTP CONNECT
```

> The lab uses a **self-signed** cert and the client runs with `--insecure` —
> fine for localhost, **not** for a real VPN. Prebuilt multi-arch images are on
> Docker Hub ([server](https://hub.docker.com/r/eljaja/bibavpn-server),
> [client](https://hub.docker.com/r/eljaja/bibavpn-client)); see
> [`docker-compose.hub.yml`](docker-compose.hub.yml) to run them without building.

### B. Real VPS + client from source

```bash
# build both binaries (Linux or WSL)
cargo build --release -p bibavpn --bin bibavpn-server
cargo build --release -p bibavpn --bin bibavpn-client

# pick secrets (both sides must agree); do not commit them
export BIBA_VPN_TOKEN="$(openssl rand -hex 16)"
export BIBA_VPN_PSK="$(openssl rand -hex 32)"
export BIBA_HOST="vpn.example.com"        # or IP
```

Server on the VPS (self-signed shown for a quick lab — use real certs in
production, see [Security](#security)):

```bash
./target/release/bibavpn-server \
  --listen 0.0.0.0:8443 --self-signed-san "$BIBA_HOST" \
  --token "$BIBA_VPN_TOKEN" --psk "$BIBA_VPN_PSK" \
  --decoy-max 24 --max-pad 64 \
  --max-ws-binary 262144 --ws-ping-secs 25
```

Client locally, pointing at the VPS:

```bash
./target/release/bibavpn-client \
  --server "$BIBA_HOST:8443" --sni "$BIBA_HOST" \
  --token "$BIBA_VPN_TOKEN" --psk "$BIBA_VPN_PSK" \
  --decoy-max 32 --max-pad 64 \
  --max-ws-binary 262144 --ws-ping-secs 25 \
  --insecure \
  --socks5 127.0.0.1:1080
```

`--insecure` disables cert verification and is **lab-only**; drop it once you
have a real certificate or use `--pin-cert <leaf.pem>`.

**Encrypted invite (optional).** Instead of sharing flags, the server can emit a
one-line config: add `--print-invite-uri`, `--invite-passphrase <pass>`,
`--invite-public "$BIBA_HOST:8443"`, and `--invite-sni "$BIBA_HOST"` to the
server flags. The client then consumes it with `--from-invite 'biba://…'` and
`--invite-passphrase <pass>`. Share the passphrase out-of-band, never alongside
the URI. See [PROTOCOL.md](PROTOCOL.md#encrypted-invite-biba).

## Using the tunnel

Point your apps at the local SOCKS5 / HTTP CONNECT endpoint:

- **Firefox:** *Settings → Network → Manual proxy*, SOCKS5 `127.0.0.1:1080`,
  "Proxy DNS when using SOCKS v5" **on**.
- **Chrome/Chromium:** `--proxy-server="socks5://127.0.0.1:1080"`.
- **curl:** `curl --socks5-hostname 127.0.0.1:1080 https://…`.
- **System-wide (Linux):** `proxychains`, or `ALL_PROXY=socks5h://127.0.0.1:1080`.

## Configuration

Every CLI flag is documented in **[AGENTS.md](AGENTS.md)**. Essentials:

- **Required:** `--server`, `--sni`, `--token`, `--psk` (no default token; denylisted
  placeholders such as `change-me` are rejected). Use **`--lab`** only for quick
  local demos. **`--psk`** is required at startup unless REALITY is fully
  configured (see below). Server `--proto-domain` (default `default`) must match the client's.
- **Shape / anti-DPI:** `--decoy-max`, `--max-pad`, `--pad-mode`,
  `--dummy-interval-secs`, `--ws-ping-secs`, `--junk-frames`, `--stealth-profile`,
  `--fingerprint`, `--ws-jitter-min-ms`/`--ws-jitter-max-ms`, `--ws-parallel`,
  `--tls-stack` (rustls default; `boring` needs the `boring-tls` build).
- **Server timing:** `--ack-profile`, `--server-ack-delay-*-ms`, `--rtt-mask-jitter-ms`.
- **Camouflage (server):** `--camouflage-dir <path>` or `--camouflage-url http://…`.
- **TLS trust (client):** real CA by default, `--pin-cert <pem>` to pin the leaf,
  `--insecure` **lab only**.
- **REALITY (optional):** server `--reality-target`, `--reality-private-key`;
  client/invite `reality_target`, `reality_public_key`, `reality_short_id`. The
  outer SNI then defaults to the front host (`vk.com:443` → SNI `vk.com`) while
  TCP still connects to `--server`. The client must also prove knowledge of
  `--token` in a mandatory AUTH frame right after the REALITY exchange (a MAC —
  the token itself never goes on the wire).

Secrets never go in the URL: the token travels in the sealed AUTH frame, and
the WebSocket path (`--ws-path`, default `/ws`) carries no credentials.

## Build from source

| Crate | Role |
| --- | --- |
| `bibavpn` | `lib` + binaries `bibavpn-server`, `bibavpn-client`, `bibavpn-mint-invite` |
| `biba` | uTLS-like TLS fingerprint helpers |
| `apps/bibavpn-jni` | Android JNI glue around `bibavpn` |
| `apps/bibavpn-desktop/src-tauri` | Tauri desktop wrapper (systray, platform proxy setup) |

```bash
cargo build --release -p bibavpn --bin bibavpn-server
cargo build --release -p bibavpn --bin bibavpn-client
cargo test --workspace
```

**BoringSSL client path** (optional; needs `cmake` / `nasm` on some platforms):
`cargo build --release -p bibavpn --features boring-tls --bin bibavpn-client`,
then `--tls-stack boring` on the client. `--pin-cert` works on both stacks.
`rust-toolchain.toml` pins the compiler so CI and local builds stay reproducible.

## Comparison

Rough positioning only.

| | **BibaVPN** | [wstunnel](https://github.com/erebe/wstunnel) | [Hysteria2](https://v2.hysteria.network/) | **REALITY** (Xray) |
| --- | --- | --- | --- | --- |
| **Transport** | TLS + WSS, PSK inner | TLS + WSS, generic | QUIC | TLS fronting / proxy |
| **DPI focus** | Explicit (fingerprints, timing, padding, decoys) | General tunneling | Throughput | Site mimicry (TLS hook) |
| **Typical role** | Single small VPS, SOCKS/CONNECT | Port forwarding | High perf | Domain/cert fronting |

BibaVPN claims no security or anonymity property beyond "harder to classify on
the wire" — see [Security](#security).

## Android & desktop

The desktop app and Android share `apps/bibavpn-desktop/` (Vite UI + Tauri
shell); Android VPN glue lives under `src-tauri/android-bibavpn-extras/`.
An iOS Packet Tunnel extension also exists under `src-tauri/ios-bibavpn-extras/`,
but it **does not forward traffic** today (Tun2socks is not wired). Treat iOS as
experimental — do not present it as a working VPN.
Prebuilt binaries come from the GitHub Actions workflows in `.github/workflows/`,
and releases are on the [Releases page](https://github.com/Eljaja/BibaVPN/releases).
See [DESIGN.md](DESIGN.md) for the shared visual language.

## Security

BibaVPN is an **experimental tunnel**, not a hardened product:

- **Keep secrets out of git.** `PSK`, `token`, and any `invite-passphrase` must
  never be committed; rotate anything that leaks.
- **`--insecure` is lab-only.** Use a real certificate (e.g. Let's Encrypt via a
  reverse proxy) or pin the leaf with `--pin-cert`.
- **Threat model:** the goal is to make the outer flow look like a long-lived
  HTTPS WebSocket to a plausible camouflage site. It is **not** anonymity
  software — the server operator sees every byte.
- **`--legacy-path-auth`** (old `/b/{token}` URL form) skips the sealed AUTH step
  and is strictly weaker; only for old clients.

Report security issues privately — see [SECURITY.md](SECURITY.md). Contributions
welcome: [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE). Third-party crates retain their own licenses.
