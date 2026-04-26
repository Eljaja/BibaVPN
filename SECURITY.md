# Security policy

## Status

BibaVPN is **experimental software**. The protocol is not frozen, there has
been no third-party audit, and there is no paid bug-bounty programme.
Assume "best effort" response.

## Reporting a vulnerability

Please do **not** open a public GitHub issue for security bugs. Instead, use
one of:

1. **GitHub private security advisory** — preferred. Go to the repository's
   *Security → Report a vulnerability* tab.
2. **Email** the maintainer listed in the commit history (you can find the
   address in recent commits on the `main` branch).

When reporting, please include:

- Affected component (`bibavpn-server`, `bibavpn-client`, Android app,
  desktop shell, specific module).
- Affected version / commit hash.
- A minimal reproducer or a clear explanation of the impact.
- Whether you would like credit in the fix commit or release notes.

We aim to acknowledge reports within **7 days** and to ship a fix or mitigation
within **30 days** for high-severity issues. Lower-severity reports are batched
into the next release.

## Scope

In scope:

- The Rust crates under `bibavpn/`, `biba/`, `bibavpn-jni/`,
  `bibavpn-desktop/src-tauri/`.
- The deployment scripts under `scripts/` when used with the documented
  environment variables.
- The Android app under `android/` (glue code on top of the Rust core).

Out of scope:

- Misuse of `--insecure`, `--legacy-path-auth`, or committing secrets from
  `.env` / `server.txt` to a fork. Those are documented footguns.
- Reverse-engineering the wire format from outside observation: the protocol
  is published in [PROTOCOL.md](PROTOCOL.md). Fingerprinting reports are
  still welcome, but not treated as vulnerabilities.
- Vulnerabilities in upstream crates — please report those upstream; we will
  pull a fixed version once available.

## Hardening checklist (operators)

- Rotate `BIBA_VPN_TOKEN`, `BIBA_VPN_PSK` and any `BIBA_INVITE_PASSPHRASE`
  the first time you stand up a server. The examples in this repo are
  placeholders.
- Use a real TLS certificate (Let's Encrypt behind a reverse proxy or
  directly) or pin the leaf with `--pin-cert`. Do **not** ship `--insecure`
  to end users.
- Keep the Docker image up to date (`docker compose build --pull`).
- Do not commit `server.txt`, `.env*`, `*.pem`, `*.key` — the repo's
  `.gitignore` already covers these.

## BibaV4 / v1.2.0 stealth modes and PSK hygiene

The **v1.2.0** line adds **DPI-oriented** controls (TLS fingerprint mimicry,
timing masks, adaptive padding, optional **userspace packet desync**). Treat
these as **defensive hardening** against classification on the path — **not**
as undetectability from the **VPS operator**, and **not** as authorization to
break local or national law.

- **PSK and tokens** remain the cryptographic core: use a **strong, unique PSK**,
  rotate on compromise, and never reuse invite passphrases as PSKs.
- **Raw sockets**, low-TTL **fake** handshakes, and **modified TCP options** (when
  implemented) typically require **administrator / root** (or `CAP_NET_RAW` on
  Linux) and can disrupt unrelated traffic if misconfigured. Only enable
  desync / fooling options on devices you own and on networks where that is
  **explicitly** permitted.
- **Third-party tests** (zapret, TSPU, GoodbyeDPI, commercial DPI boxes) are
  **environment-specific**; maintainers cannot guarantee a “pass” in your
  country, ISP, or year. Document results as best-effort.

See also [PROTOCOL.md — BibaV4](PROTOCOL.md#bibav4-v120-target-specification) and
[AGENTS.md — stealth checklist](AGENTS.md#v120-bibav4-stealth-checklist).
