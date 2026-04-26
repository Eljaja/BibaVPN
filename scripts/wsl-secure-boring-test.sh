#!/usr/bin/env bash
# WSL: build bibavpn with boring-tls, run unit tests, then two integration smokes:
#  1) rustls + --pin-cert + strong token/PSK/proto (TLS verification to pinned leaf)
#  2) --tls-stack boring + same secrets; for self-signed cert use --insecure (boring+pin not supported yet in code)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export RUST_BACKTRACE="${RUST_BACKTRACE:-0}"

echo "=============================================="
echo "  cargo test -p bibavpn --features boring-tls"
echo "=============================================="
cargo test -p bibavpn --features boring-tls

echo ""
echo "=============================================="
echo "  cargo build -p bibavpn --features boring-tls --release"
echo "=============================================="
cargo build -p bibavpn --features boring-tls --release

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"; kill "${SRV_PID:-}" 2>/dev/null || true' EXIT

CERT="$TMPDIR/cert.pem"
KEY="$TMPDIR/key.pem"
openssl req -x509 -newkey rsa:2048 -keyout "$KEY" -out "$CERT" -days 1 -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null || \
openssl req -x509 -newkey rsa:2048 -keyout "$KEY" -out "$CERT" -days 1 -nodes \
  -subj "/CN=localhost"

TOKEN="st-$(openssl rand -hex 24)"
PSK="psk-$(openssl rand -hex 32)"
DOMAIN="secure-lab-kdf-$(openssl rand -hex 4)"
PORT=18543
SOCKS_R=127.0.0.1:21080
SOCKS_B=127.0.0.1:21081

SERVER_BIN="$ROOT/target/release/bibavpn-server"
CLIENT_BIN="$ROOT/target/release/bibavpn-client"

echo ""
echo "=== Integration: server (cert+key, v3 PSK, adaptive pad) ==="
"$SERVER_BIN" \
  --listen "127.0.0.1:$PORT" \
  --cert "$CERT" \
  --key "$KEY" \
  --token "$TOKEN" \
  --psk "$PSK" \
  --proto-domain "$DOMAIN" \
  --ws-path /ws \
  --pad-mode adaptive \
  --ack-profile balanced \
  &
SRV_PID=$!
sleep 2

echo "=== Client A: rustls (default) + --pin-cert + strong secrets ==="
"$CLIENT_BIN" \
  --server "127.0.0.1:$PORT" \
  --sni localhost \
  --token "$TOKEN" \
  --psk "$PSK" \
  --proto 3 \
  --proto-domain "$DOMAIN" \
  --pin-cert "$CERT" \
  --socks5 "$SOCKS_R" \
  --pad-mode adaptive \
  --max-pad 64 \
  --decoy-max 0 &
CL_PID=$!
sleep 2
curl -fsS --connect-timeout 12 --socks5-hostname "$SOCKS_R" http://example.com/ | head -c 100
echo
kill "$CL_PID" 2>/dev/null || true
wait "$CL_PID" 2>/dev/null || true
sleep 1

echo "=== Client B: --tls-stack boring + same secrets (self-signed → --insecure; pin unsupported with boring) ==="
echo "    (see local_client: Boring + pin-cert is rejected until implemented)"
"$CLIENT_BIN" \
  --server "127.0.0.1:$PORT" \
  --sni localhost \
  --token "$TOKEN" \
  --psk "$PSK" \
  --proto 3 \
  --proto-domain "$DOMAIN" \
  --insecure \
  --tls-stack boring \
  --socks5 "$SOCKS_B" \
  --pad-mode adaptive \
  --max-pad 64 \
  --decoy-max 0 \
  &
CL_PID=$!
sleep 2
curl -fsS --connect-timeout 12 --socks5-hostname "$SOCKS_B" http://example.com/ | head -c 100
echo
kill "$CL_PID" 2>/dev/null || true
wait "$CL_PID" 2>/dev/null || true

kill "$SRV_PID" 2>/dev/null || true
wait "$SRV_PID" 2>/dev/null || true
SRV_PID=

echo ""
echo "OK: unit tests + rustls+pin smoke + boring-stack smoke passed."
