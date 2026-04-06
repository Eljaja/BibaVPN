# BibaVPN

Local **SOCKS5** and optional **HTTP CONNECT** over **TLS + WebSocket** to an entry server; the server opens outbound **TCP** to the target `host:port`. Optional **BibaV2**: shared PSK, HELLO/ACK, ChaCha20-Poly1305, and random decoy per frame. **BibaV2.1** adds a max WS binary size, periodic WS Ping, configurable upgrade headers, and early-session noise.

Developer details: [AGENT.md](AGENT.md).

---

## End-to-end picture

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
    Q -->|yes| HA[3 HELLO mag+rand 32B → ACK mag+rand+MAC16]
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

## Build and run (short)

```bash
cargo build --release -p bibavpn --bin bibavpn-server
cargo build --release -p bibavpn --bin bibavpn-client
```

Flags, Docker, and the remote-only client are described in [AGENT.md](AGENT.md).

Workspace crates also include `bibavpn-jni` (Android JNI) and `bibavpn-desktop` (desktop helper); see `android/` for the Android app.

## Security

Treat PSK and path token as **secrets** — do not commit them. For production use proper certificates and avoid `--insecure` on the client.
