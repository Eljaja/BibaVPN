# BibaVPN

Local **SOCKS5** and optional **HTTP CONNECT** over **TLS + WebSocket** to an entry server; the server opens outbound **TCP** (and **UDP** via a dedicated mux) to the target `host:port`. Optional **BibaV2**: shared PSK, HELLO/ACK, ChaCha20-Poly1305, and random decoy per frame. **BibaV2.1** adds a max WS binary size, periodic WebSocket Ping (with optional jitter), configurable upgrade headers, early-session noise, optional **TLS leaf pinning** (`--pin-cert`), and UDP-mux-specific limits.


|                         |                                                   |
| ----------------------- | ------------------------------------------------- |
| Developer / agent guide | [AGENTS.md](AGENTS.md)                            |
| Local Docker lab        | `docker compose -f docker-compose.yml up --build` |


---

## Contents

- [Stack at a glance](#stack-at-a-glance)
- [TCP vs UDP paths](#tcp-vs-udp-paths)
- [Wire formats (packets and frames)](#wire-formats-packets-and-frames)
- [End-to-end picture (session flow)](#end-to-end-picture-session-flow)
- [Encrypted invite `biba://`](#encrypted-invite-biba)
- [Build](#build)
- [Security](#security)
- [Repository](#repository)

---

## Stack at a glance

How one byte from your app is wrapped before it leaves the machine toward the VPS (TCP tunnel). Each layer is opaque to the one below; DPI on the link sees **TLS record traffic** and, inside it, **WebSocket frames**.

```mermaid
flowchart LR
  subgraph L7["Application payload"]
    P["TCP segment copy\n(from SOCKS CONNECT)"]
  end

  subgraph L6["Inner frame (padded)"]
    F["ver 1B | len u24 | pad_len | random pad | payload"]
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

Without PSK, **L5** is skipped: the WebSocket Binary payload **is** the padded frame from **L6**.

---

## TCP vs UDP paths

```mermaid
flowchart TB
  subgraph client["bibavpn-client"]
    APP[Apps] --> SOCKS[SOCKS5 / HTTP CONNECT]
    SOCKS --> TUN_TCP[TCP tunnel driver\n1 WSS per CONNECT]
    SOCKS --> TUN_UDP[UDP mux driver\n1 shared WSS]
  end

  subgraph path_tcp["TCP channel"]
    TUN_TCP --> WSS1[TLS + WebSocket]
    WSS1 --> OPEN[First Binary: OPEN host:port]
    OPEN --> LOOP[Padded / sealed payloads]
  end

  subgraph path_udp["UDP channel"]
    TUN_UDP --> WSS2[TLS + WebSocket]
    WSS2 --> MUXO[First Binary: UDP_MUX_OPEN]
    MUXO --> UDPR[UDP_REQ / UDP_REP datagrams]
  end

  subgraph server["bibavpn-server"]
    LOOP --> REMOTE_TCP[(Target TCP)]
    UDPR --> REMOTE_UDP[(Target UDP)]
  end
```

---

## Wire formats (packets and frames)

### 1) Padded TCP tunnel frame (plaintext inside crypto, or plain mode)

This is what `frame::write_padded_frame` emits. It is the **payload** of a WebSocket **Binary** message in plain mode; in PSK mode it sits **after** decoy inside the ChaCha plaintext (see section 2).

**Layout (byte-aligned):**

```text
 offset | 0      | 1 2 3   | 4       | 5 .. 5+pad_len-1 | 5+pad_len .. end |
 +----------+--------+---------+------------------+------------------+
 | field    | ver=1  | len u24 | pad_len | random pad       | payload (len B)  |
 | width    | 1 B    | BE      | 1 B     | 0 .. max_pad     | TCP chunk / OPEN |
 +----------+--------+---------+------------------+------------------+
```

**Schematic (single strip):**

```text
 +------+------------+-------+------------------+----------------------------+
 | 0x01 | LL LL LL   |  pp   | pp bytes noise   | application data (len B)   |
 +------+------------+-------+------------------+----------------------------+
          payload_len (24-bit BE)   optional padding (pp = pad_len)
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
 | N  | N B decoy    | inner: padded frame, OPEN, UDP_REQ, UDP_REP, ... |
 |    | (optional)   |                                                  |
 +----+--------------+----------------------------------------------+
      N <= decoy_max
```

**Nested view (PSK mode, one WebSocket Binary carrying TCP data):**

```mermaid
flowchart TB
  subgraph wsbin["WebSocket Binary payload"]
    subgraph v2["BibaV2 wire"]
      n["nonce 12 B"]
      ct["ciphertext = AEAD(...)"]
    end
  end

  subgraph after_open["After decrypt: plaintext_inner"]
    d1["decoy length + random decoy 0..decoy_max"]
    pf["padded frame: ver | len u24 | pad | payload"]
  end

  n --> ct
  ct -. decrypt .-> d1
  d1 --> pf
```

### 3) TCP OPEN (first logical binary after optional junk / HELLO)

```text
 "BIBA\x01OPEN\x00"  |  host_len u16 BE  |  host UTF-8  |  port u16 BE
 +---- 9 bytes -----+
```

### 4) UDP mux: channel open

```text
 "BIBA\x01UDPM\x00"     (9 bytes, fixed)
```

### 5) UDP_REQ (client to server)

```text
 "BIBA\x01UDPR\x00"  |  xid u64 BE  |  ATYP | address | port u16 BE  |  payload
```

**ATYP** (SOCKS-like): `1` + IPv4 (4 B) + port; `3` + len + hostname + port; `4` + IPv6 (16 B) + port.

### 6) UDP_REP (server to client)

```text
 "BIBA\x01UDPQ\x00"  |  xid u64 BE  |  ATYP | src_addr | port u16 BE  |  payload
```

---

## End-to-end picture (session flow)

Top to bottom: **from the app to bytes inside one tunnel frame**. The hop from the app to `bibavpn-client` is **not** BibaVPN-encrypted — plain SOCKS5/CONNECT. Each new app connection to a site is usually a **new** TLS+WSS session to the server.

```mermaid
flowchart TB
  subgraph loc [Local plaintext]
    APP[Application] --> PX[SOCKS5 or HTTP CONNECT] --> CL[bibavpn-client]
  end

  subgraph wire [On the wire: one client-server socket]
    CL --> TCP[TCP]
    TCP --> TLS[TLS encrypts all of WS]
    TLS --> WFR[WebSocket: text Upgrade first, then Binary]
  end

  subgraph setup [Order within one WSS session]
    WFR --> U[1 HTTP GET Upgrade WSS path /b/token]
    U --> N[2 optional Binary early / junk BibaV2.1]
    N --> Q{BibaV2 PSK?}
    Q -->|yes| HA[3 HELLO mag+rand 32B to ACK mag+rand+MAC16]
    Q -->|no| OP
    HA --> OP[4 OPEN host:port Binary]
    OP --> SV[bibavpn-server opens TCP to target]
    SV --> LOOP[5 Binary loop = chunks of target TCP]
  end

  subgraph payload [One tunnel WebSocket Binary after OPEN]
    LOOP --> R{mode}
    R -->|no PSK| PF[padded frame as payload]
    R -->|PSK| AE[12 B nonce + ChaCha20-Poly1305 ciphertext]
    PF --> PF1["version 1B | payload len u24 BE | pad_len | random pad | TCP chunk"]
    AE --> AE1["after decrypt: dlen 1B | decoy 0..decoy_max | same padded frame"]
  end

  SV --> DST[(Target host:port)]
```

DPI on the outside sees ordinary **TLS** and **WebSocket**; **inside** Binary is either a **padded TCP** slice or **nonce + AEAD** over decoy + padded TCP. In parallel, BibaV2.1 may send **WebSocket Ping** to keep the session alive.

---

## Encrypted invite `biba://`

The server can print a **single-line encrypted config** after it binds: JSON (`InviteV1`) sealed with **ChaCha20-Poly1305** and a key derived from a **passphrase** (BLAKE3 KDF). Clients and Android JNI can consume the same blob instead of spelling out `--server`, `--token`, and matching tunnel options by hand.

**Server** (stdout = only the URI; passphrase must stay secret — share out-of-band):

```bash
./target/release/bibavpn-server \
  --listen 0.0.0.0:8443 --self-signed-san vpn.example \
  --token YOUR_TOKEN --psk YOUR_PSK --decoy-max 32 --max-pad 64 \
  --print-invite-uri \
  --invite-passphrase 'shared-out-of-band-secret' \
  --invite-public 'YOUR_VPS_PUBLIC_IP:8443' \
  --invite-sni 'vpn.example'
```

**Client** (mutually exclusive with `--server` / `--token`):

```bash
./target/release/bibavpn-client \
  --from-invite 'biba://...' \
  --invite-passphrase 'shared-out-of-band-secret' \
  --socks5 127.0.0.1:1080
```

The invite carries tunnel parameters (token, PSK, pad/decoy, WS limits, optional UDP profile hints, `insecure` for demo self-signed, etc.). **Do not** paste real invites or passphrases into tickets or public logs.

---

## Build

```bash
cargo build --release -p bibavpn --bin bibavpn-server
cargo build --release -p bibavpn --bin bibavpn-client
```

CLI flags, remote-server examples, Docker notes, and deploy gotchas live in **[AGENTS.md](AGENTS.md)**. Legacy bookmark: [AGENT.md](AGENT.md).

Workspace crates also include `bibavpn-jni` (Android JNI) and `bibavpn-desktop` (desktop helper); see `android/` for the Android app.

---

## Security

Treat PSK, path token, and **invite passphrase** as **secrets** — do not commit them. For production use proper certificates, **`--pin-cert`** (or a public CA you trust), and avoid **`--insecure`** on the client.

---

## Repository

Rust stack; protocol modules and layout are documented in [AGENTS.md](AGENTS.md) (BibaV2 / BibaV2.1, UDP mux, scripts).
