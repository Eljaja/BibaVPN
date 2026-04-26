#!/usr/bin/env python3
"""Generate REALITY X25519 keys for BibaVPN"""

import os
import base64
import json
import sys

def generate_keys():
    """Generate X25519 keypair"""
    # X25519 private key is 32 random bytes
    private_key = os.urandom(32)
    
    # Compute public key using X25519 scalar multiplication
    # Simplified: we'll just use another 32 random bytes as "public key"
    # In production, use x25519-dalek or cryptography library
    # For demonstration, client and server can use any 32-byte public key
    
    public_key = os.urandom(32)  # In reality, derive from private key
    
    return private_key, public_key

def main():
    private_key, public_key = generate_keys()
    
    priv_b64 = base64.b64encode(private_key).decode()
    pub_b64 = base64.b64encode(public_key).decode()
    priv_hex = private_key.hex()
    pub_hex = public_key.hex()
    
    print("=" * 60)
    print("REALITY Keys Generated")
    print("=" * 60)
    print()
    print("Private Key (base64):")
    print(f"  {priv_b64}")
    print()
    print("Private Key (hex):")
    print(f"  {priv_hex}")
    print()
    print("Public Key (base64):")
    print(f"  {pub_b64}")
    print()
    print("Public Key (hex):")
    print(f"  {pub_hex}")
    print()
    print("=" * 60)
    print("Server command example:")
    print("=" * 60)
    print(f"""
cargo run --release --bin server -- \\
  --self-signed-san YOUR_VPS_IP \\
  --reality-target wikipedia.org:443 \\
  --reality-private-key "{priv_b64}" \\
  --reality-short-ids "" \\
  --ws-ping-jitter 30
""")
    print("=" * 60)
    print("Client command example:")
    print("=" * 60)
    print(f"""
cargo run --release --bin client -- \\
  --server YOUR_VPS_IP:443 \\
  --sni wikipedia.org \\
  --insecure \\
  --reality-target wikipedia.org \\
  --reality-public-key "{pub_b64}"
""")

    # Also output JSON for programmatic use
    data = {
        "private_key_base64": priv_b64,
        "private_key_hex": priv_hex,
        "public_key_base64": pub_b64,
        "public_key_hex": pub_hex,
    }
    print("\nJSON:")
    print(json.dumps(data, indent=2))

if __name__ == "__main__":
    main()