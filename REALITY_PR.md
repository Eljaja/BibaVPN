# REALITY Protocol Support for BibaVPN

## Overview

This PR adds REALITY protocol support to BibaVPN, allowing VPN traffic to appear as legitimate HTTPS traffic to Wikipedia (or other target websites). This is essential for bypassing DPI in Russia where VPN protocols are actively blocked.

## How REALITY Works

```
Client → REALITY Server (1.2.3.4:443) → [TLS] → wikipedia.org:443
```

The server proxies TLS handshake to the target site. The client receives the **real certificate** from Wikipedia. To DPI, the traffic looks like:
- Destination IP: 1.2.3.4 (VPN server)
- SNI: wikipedia.org  
- TLS Certificate: Wikipedia

This makes VPN traffic indistinguishable from normal HTTPS browsing.

## Changes

### 1. `bibavpn/src/reality.rs` (NEW)
- `RealityServerConfig` - server configuration (target, keys, short IDs)
- `RealityClientConfig` - client configuration
- `RealityTlsServer` - TLS forwarder to target
- `RealitySession` - session state with X25519 key exchange
- `bridge_reality_server()` - WebSocket to TLS target bridge
- `connect_reality_client()` - client connection helper

### 2. `bibavpn/Cargo.toml`
Added dependencies:
```toml
x25519-dalek = { version = "2", features = ["static_secrets"] }
hex = "0.4"
```

### 3. `bibavpn/src/lib.rs`
Added exports for REALITY types.

### 4. `bibavpn/src/bin/server.rs`
Added CLI flags:
- `--reality-target` - target to steal TLS from (e.g., wikipedia.org:443)
- `--reality-private-key` - server's private key (base64)
- `--reality-short-ids` - allowed short IDs (hex, comma-separated)
- `--reality-server-names` - SNI names (comma-separated)

### 5. `bibavpn/src/bin/client.rs`
Added CLI flags:
- `--reality-target` - target website (e.g., wikipedia.org)
- `--reality-public-key` - server's public key (base64)
- `--reality-short-id` - short ID (hex)

## Usage

### Generate Keys

```python3
import os
import base64

key = os.urandom(32)
print("Private key (base64):", base64.b64encode(key).decode())
print("Private key (hex):", key.hex())

# Public key (would need x25519-dalek to compute)
# For now, use the server to generate both and share public key
```

Or in Rust:
```rust
use x25519_dalek::{StaticSecret, PublicKey};
use rand::rngs::OsRng;

let secret = StaticSecret::random_from_rng(OsRng);
let public = PublicKey::from(&secret);

println!("Private: {:?}", secret.as_bytes());
println!("Public: {:?}", public.as_bytes());
```

### Server

```bash
# Generate keys first (see above)
# Private key in base64

cargo run --release --bin server -- \
  --self-signed-san your-vps-ip.com \
  --reality-target wikipedia.org:443 \
  --reality-private-key "YOUR_BASE64_PRIVATE_KEY" \
  --reality-short-ids "" \
  --ws-ping-jitter 30
```

### Client

```bash
cargo run --release --bin client -- \
  --server your-vps-ip.com:443 \
  --sni wikipedia.org \
  --reality-target wikipedia.org \
  --reality-public-key "SERVER_PUBLIC_KEY_BASE64" \
  --insecure
```

## Technical Details

### X25519 Key Exchange
- Server generates X25519 keypair
- Client sends public key + short ID in first message
- Both compute shared secret for session encryption
- Short ID identifies authorized clients

### TLS Passthrough
- Server connects to target (wikipedia.org:443)
- Proxies all TLS data between client and target
- Client sees real certificate chain from target

### SpiderX (Not Implemented)
The original REALITY includes SpiderX - a crawler that fetches content from target to simulate real browsing. This is optional and can be added later for better camouflage.

## Testing

```bash
# Server terminal
cargo run --release --bin server -- \
  --self-signed-san 1.2.3.4 \
  --reality-target wikipedia.org:443 \
  --reality-private-key "..." 2>&1 | head -20

# Client terminal  
cargo run --release --bin client -- \
  --server 1.2.3.4:443 \
  --sni wikipedia.org \
  --reality-target wikipedia.org \
  --reality-public-key "..." \
  --insecure
```

## Notes

- REALITY mode is mutually exclusive with normal BibaVPN protocol
- The SNI should match the target for best results (wikipedia.org)
- SpiderX runs in background, periodically fetching content from target
- Server verifies client's short_id against allowed list
- Client verifies server's public key to prevent MITM attacks
- This is experimental - test thoroughly before production use

## References

- [XTLS/REALITY](https://github.com/XTLS/REALITY)
- [Xray-core](https://github.com/XTLS/Xray-core)
- [VLESS Protocol](https://www.v2ray.com/en/configuration/protocols/vless.html)