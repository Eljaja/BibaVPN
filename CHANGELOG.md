# Changelog

All notable changes to BibaVPN are documented here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.2.0] — Unreleased (branch `v1.2.0`)

**Theme:** BibaV4 / full DPI-stealth 2026 — **breaking** wire and CLI vs earlier
Biba v3 lines. There is **no** backward-compatibility guarantee for v1.2.0: old
clients and servers must be upgraded as a pair.

### Target (specification of record)

- **P0 — TLS / fingerprinting:** BoringSSL-class stack (or equivalent), ClientHello
  mimicry (Chrome 132+ default), full GREASE, randomized extension order,
  optional `--tls-fragment` (split ClientHello and application data over 2–4 TCP
  segments).
- **P0 — Cross-layer RTT:** server delayed-ACK window; 2–4 parallel WebSocket
  sessions with round-robin load inside mux; `--rtt-mask` / decoy high-variance
  RTT paths (NDSS-style fingerprint mitigation).
- **P0 — Traffic shaping:** `--pad-mode adaptive` (default), burst patterns
  inspired by real HTTP/2 browser stacks, `--ws-jitter` on outbound frames.
- **P0 — Decoy traffic:** `--decoy-mode browser` with real-site lists and
  browser-like request headers; short idle-burst sessions.
- **P0 — Client desync (userspace):** `--desync-mode` (split2 / fake split /
  disorder), low-TTL fake ClientHello injection, optional TCP options games  
  (requires platform privileges — see [SECURITY.md](SECURITY.md)).
- **P1 (may slip to 1.2.1):** H2 WebSocket upgrade, host/header spoofing, IP
  id/TTL play, UDP-mux desync.
- **Quality bar:** unit + integration tests for new subsystems; CI lab with
  traffic capture; throughput regression not more than ~10% vs pre-change
  baseline on the local bench script; documentation in README / PROTOCOL /
  AGENTS / this file.

### What shipped in the repo (incremental)

Entries will be added as subsystems land. Pre-release documentation may
describe the **target** BibaV4 behaviour before every flag is implemented.

### Release notes (draft)

- See **README** “v1.2.0 & BibaV4” and **PROTOCOL** “BibaV4” for operator and
  protocol details.
- **SECURITY:** strict PSK hygiene and cautions for raw-socket / desync modes.

---

## Earlier releases

Prior changelog entries were not maintained in-tree; use `git log` and GitHub
releases for history before 1.2.0.

[1.2.0]: https://github.com/Eljaja/BibaVPN/compare/main...v1.2.0
