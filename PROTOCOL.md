# BibaVPN — protocol and wire formats

BibaVPN is a local **SOCKS5** (and optional **HTTP CONNECT**) front that tunnels
traffic over **TLS + WebSocket** to a remote entry server, which in turn dials
the target `host:port` over **TCP** (with a dedicated mux for **UDP**).

This document specifies the on-wire layers. For install / run instructions see
**[README.md](README.md)**; for contributor notes see **[AGENTS.md](AGENTS.md)**.

---

## Contents

- [Stack at a glance](#stack-at-a-glance)
- [TCP vs UDP paths](#tcp-vs-udp-paths)
- [Wire formats (packets and frames)](#wire-formats-packets-and-frames)
- [End-to-end picture (session flow)](#end-to-end-picture-session-flow)
- [Encrypted invite `biba://`](#encrypted-invite-biba)

---

## Stack at a glance

How one byte from your app is wrapped before it leaves the machine toward the VPS (TCP tunnel). Each layer is opaque to the one below; DPI on the link sees **TLS record traffic** and, inside it, **WebSocket frames**.

```mermaid
flowchart LR
  subgraph L7["Application payload"]
    P["TCP segment copy\n(from SOCKS CONNECT)"]
  end

  subgraph L6["Inner frame (padded)"]
    F["ver 1B | len u24 | pad_len | pad | payload"]
  end

  subgraph L5["BibaV2 (optional)"]
    V2["decoy_len | random decoy | padded frame"]
    AEAD["ChaCha20-Poly1305 to ciphertext"]
    NONCE["12-byte nonce"]
    W2["on wire: nonce + ciphertext"]
  end

  subgraph L4["WebSocket"]
    WS["Binary frame\n(opcode 2)"]
  end

  subgraph L3["TLS"]
    TLS["Encrypted records\n(whole WS stream)"]
  end

  P --> F
  F --> V2
  V2 --> AEAD
  NONCE --> W2
  AEAD --> W2
  W2 --> WS
  WS --> TLS
```

Without PSK, **L5** is skipped: the WebSocket Binary payload **is** the padded frame from **L6**. Padding length can follow **uniform random** or **HTTP-like size buckets** (`--pad-mode`).

---

## TCP vs UDP paths

```mermaid
flowchart TB
  subgraph client["bibavpn-client"]
    APP[Apps] --> SOCKS[SOCKS5 / HTTP CONNECT]
    SOCKS --> TUN_TCP[TCP: mux driver\n1 shared WSS default]
    SOCKS --> TUN_UDP[UDP mux driver\n1 shared WSS]
  end

  subgraph path_tcp["TCP channel (default)"]
    TUN_TCP --> WSS1[TLS + WebSocket]
    WSS1 --> MUXO2[First logical: MUX_OPEN magic]
    MUXO2 --> STREAMS[Per-stream mux records\nOPEN target / DATA / CLOSE / WIN]
  end

  subgraph path_tcp_legacy["TCP legacy (--no-mux)"]
    TUN_TCP -.-> WSSL[1 WSS per SOCKS CONNECT]
    WSSL -.-> OPENL[First Binary: OPEN host:port]
    OPENL -.-> LOOPL[Padded / sealed payloads]
  end

  subgraph path_udp["UDP channel"]
    TUN_UDP --> WSS2[TLS + WebSocket]
    WSS2 --> MUXO[First Binary: UDP_MUX_OPEN]
    MUXO --> UDPR[UDP_REQ / UDP_REP datagrams]
  end

  subgraph server["bibavpn-server"]
    STREAMS --> REMOTE_TCP[(Target TCP)]
    LOOPL -.-> REMOTE_TCP
    UDPR --> REMOTE_UDP[(Target UDP)]
  end
```

---

## Wire formats (packets and frames)

### 1) Padded TCP tunnel frame (plaintext inside crypto, or plain mode)

This is what `frame::write_padded_frame` / `write_padded_frame_with_mode` emits. It is the **payload** of a WebSocket **Binary** message in plain mode; in PSK mode it sits **after** decoy inside the ChaCha plaintext (see section 2).

**Layout (byte-aligned):**

```text
 offset | 0      | 1 2 3   | 4       | 5 .. 5+pad_len-1 | 5+pad_len .. end |
 +----------+--------+---------+------------------+------------------+
 | field    | ver=1  | len u24 | pad_len | random pad       | payload (len B)  |
 | width    | 1 B    | BE      | 1 B     | 0 .. max_pad     | TCP chunk / OPEN |
 +----------+--------+---------+------------------+------------------+
```

### 2) BibaV2 outer wrapper (inside one WebSocket Binary)

After HELLO/ACK, each direction uses **ChaCha20-Poly1305** with a **12-byte nonce** (see `crypto_layer.rs`).

**On the wire:**

```text
 +-------------+------------------------------------------------------+
 | nonce 12 B  | ciphertext = AEAD( plaintext_inner )               |
 +-------------+------------------------------------------------------+
```

**Plaintext inner (before AEAD):**

```text
 +----+--------------+----------------------------------------------+
 | N  | N B decoy    | inner: padded frame, OPEN, mux record, UDP_… |
 |    | (optional)   |                                              |
 +----+--------------+----------------------------------------------+
      N <= decoy_max
```

### 3) AUTH (after WS upgrade; token not in URL)

```text
 "BIBA\x01AUTH\x00"  |  token_len u16 BE  |  token UTF-8
 +---- 9 bytes -----+
```

### 4) TCP OPEN (legacy single-stream mode, first logical binary after optional junk / HELLO)

```text
 "BIBA\x01OPEN\x00"  |  host_len u16 BE  |  host UTF-8  |  port u16 BE
 +---- 9 bytes -----+
```

### 5) TCP mux: capability and stream records

**Channel open (client → server), fixed magic:**

```text
 "BIBA\x01MUXO\x00"     (9 bytes)
```

**Mux record (inside one padded inner payload):**

```text
 stream_id u32 BE | flags u8 | payload_len u32 BE | payload
```

Flags include stream open, data, close, RST, and window update (flow control). See `tcp_mux.rs`.

### 6) UDP mux: channel open

```text
 "BIBA\x01UDPM\x00"     (9 bytes, fixed)
```

### 7) UDP_REQ (client to server)

```text
 "BIBA\x01UDPR\x00"  |  xid u64 BE  |  ATYP | address | port u16 BE  |  payload
```

**ATYP** (SOCKS-like): `1` + IPv4 (4 B) + port; `3` + len + hostname + port; `4` + IPv6 (16 B) + port.

### 8) UDP_REP (server to client)

```text
 "BIBA\x01UDPQ\x00"  |  xid u64 BE  |  ATYP | src_addr | port u16 BE  |  payload
```

---

## End-to-end picture (session flow)

Top to bottom: **from the app to bytes inside one tunnel frame**. The hop from the app to `bibavpn-client` is **not** BibaVPN-encrypted — plain SOCKS5/CONNECT.

**Default TCP (multiplexed):** one **TLS + WSS** per client process; many SOCKS connections become **mux streams** on that socket.

```mermaid
flowchart TB
  subgraph loc [Local plaintext]
    APP[Application] --> PX[SOCKS5 or HTTP CONNECT] --> CL[bibavpn-client]
  end

  subgraph wire [On the wire: outer client-server socket]
    CL --> TCP[TCP]
    TCP --> TLS[TLS encrypts all of WS]
    TLS --> WFR[WebSocket: HTTP Upgrade, then Binary]
  end

  subgraph setup [Order within one WSS session]
    WFR --> U[1 GET Upgrade to configured path e.g. /ws — no token in URL]
    U --> N[2 optional Binary noise / junk BibaV2.1]
    N --> AU[3 AUTH binary with token]
    AU --> Q{BibaV2 PSK?}
    Q -->|yes| HA[4 HELLO / ACK]
    Q -->|no| MX
    HA --> MX[5 MUX_OPEN magic]
    MX --> ST[6 Stream OPEN + DATA mux records to target]
    ST --> SV[bibavpn-server connects per stream]
    SV --> LOOP[7 Binary loop: padded / sealed payloads]
  end

  subgraph payload [One tunnel WebSocket Binary in data phase]
    LOOP --> R{mode}
    R -->|no PSK| PF[padded frame as payload]
    R -->|PSK| AE[12 B nonce + ChaCha20-Poly1305 ciphertext]
    PF --> PF1["version 1B | payload len u24 BE | pad_len | pad | inner"]
    AE --> AE1["after decrypt: dlen 1B | decoy 0..decoy_max | same inner"]
  end

  SV --> DST[(Target host:port)]
```

**Legacy TCP (`--no-mux`):** each SOCKS CONNECT opens a **new** WSS; step 5 is **OPEN host:port** instead of MUX_OPEN + stream records.

DPI on the outside sees **TLS** and **WebSocket**; **inside** Binary is either **padded** data or **nonce + AEAD**. BibaV2.1 may send **WebSocket Ping** and optional **idle dummy** padded frames.

---

## Encrypted invite `biba://`

The server can print a **single-line encrypted config** after it binds: JSON (`InviteV1`) sealed with **ChaCha20-Poly1305** and a key derived from a **passphrase** (BLAKE3 KDF). Clients and Android JNI can consume the same blob instead of spelling out `--server`, `--token`, and matching tunnel options by hand.

Invite JSON may include optional **`ws_path`**, **`pad_mode`**, **`dummy_interval_secs`** (and existing tunnel fields). **Do not** paste real invites or passphrases into tickets or public logs.

**Server** (stdout = only the URI; passphrase must stay secret — share out-of-band):

```bash
./target/release/bibavpn-server \
  --listen 0.0.0.0:8443 --self-signed-san vpn.example.com \
  --token "$BIBA_VPN_TOKEN" --psk "$BIBA_VPN_PSK" --decoy-max 32 --max-pad 64 \
  --ws-path /ws \
  --print-invite-uri \
  --invite-passphrase "$BIBA_INVITE_PASSPHRASE" \
  --invite-public 'YOUR_VPS_PUBLIC_IP:8443' \
  --invite-sni 'vpn.example.com'
```

**Client** (mutually exclusive with `--server` / `--token`):

```bash
./target/release/bibavpn-client \
  --from-invite 'biba://...' \
  --invite-passphrase "$BIBA_INVITE_PASSPHRASE" \
  --socks5 127.0.0.1:1080
```

---

## BibaV2 summary

- Enabled with matching `--psk` and `--decoy-max` on client and server.
- HELLO: magic `BIBV2HL1` + 32-byte client random.
- ACK: `BIBV2ACK1` + server random + 16-byte keyed MAC (BLAKE3 over PSK).
- Directional keys: `bibavpn.v2.c2s` / `bibavpn.v2.s2c`.
- On the wire: 12-byte nonce + ciphertext; plaintext is optional decoy `0..N` bytes then **inner payload** (padded frame or mux record, etc.).

## BibaV2.1 transport knobs

Compatible with the same BibaV2 PSK/decoy when both ends match.

- `--ws-ping-secs`, `--ws-ping-jitter-percent`, `--ws-binary-send-jitter-ms`
- `--max-ws-binary` — cap outgoing WS binary; mux code reserves **9 bytes** for the mux record header when chunking TCP.
- `--udp-max-pad`, `--udp-max-ws-binary`, `--udp-mux-reply-timeout-secs`
- `--ws-host`, `--ws-origin`, `--ws-user-agent`, `--ws-accept-language`, `--ws-header`
- `--early-ws-frames`, `--junk-frames`
- `--pin-cert` (client) — incompatible with `--insecure`
- `--ws-path` — WebSocket path; token via **AUTH** (default `/ws`)
- `--legacy-path-auth` (server) — accept old `/b/{token}` without AUTH (less safe)
- `--pad-mode random|http-buckets`
- `--dummy-interval-secs` — idle empty padded frames (`0` = off)
- `--decoy-gets`, `--decoy-gets-interval-secs`, `--decoy-gets-paths` — client-only decoy HTTPS fetches
- `--camouflage-dir`, `--camouflage-url` (`http://` upstream only) — server camouflage

Wire-format changes require **both** client and server updates.
