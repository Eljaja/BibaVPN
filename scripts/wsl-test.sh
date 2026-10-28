#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# PSK is mandatory for proto 3 (see startup_secrets::require_psk); this is a
# throwaway loopback value, never a real secret.
PSK="${BIBAVPN_PSK:-wsl-lab-psk}"
BODY="$(mktemp)"

cargo build --message-format=short
SERVER_BIN="$ROOT/target/debug/bibavpn-server"
CLIENT_BIN="$ROOT/target/debug/bibavpn-client"

cleanup() {
  kill "${SRV_PID:-}" "${CL_PID:-}" 2>/dev/null || true
  rm -f "$BODY"
}
trap cleanup EXIT

echo "=== Default mode (proto 3 + PSK) ==="
"$SERVER_BIN" --listen 127.0.0.1:18443 --self-signed-san localhost --token wsl-test-token --psk "$PSK" &
SRV_PID=$!
sleep 1
"$CLIENT_BIN" \
  --server 127.0.0.1:18443 \
  --sni localhost \
  --token wsl-test-token \
  --insecure \
  --socks5 127.0.0.1:11080 \
  --psk "$PSK" \
  --junk-frames 1 &
CL_PID=$!
sleep 1
curl -fsS --connect-timeout 8 --max-time 20 --socks5-hostname 127.0.0.1:11080 http://example.com/ -o "$BODY"
head -c 60 "$BODY"
echo
cleanup
SRV_PID= CL_PID=
sleep 1

echo "=== BibaV2 PSK + decoy ==="
"$SERVER_BIN" \
  --listen 127.0.0.1:18444 \
  --self-signed-san localhost \
  --token wsl-v2 \
  --psk "$PSK" \
  --decoy-max 12 \
  &
SRV_PID=$!
sleep 1
"$CLIENT_BIN" \
  --server 127.0.0.1:18444 \
  --sni localhost \
  --token wsl-v2 \
  --insecure \
  --socks5 127.0.0.1:11081 \
  --psk "$PSK" \
  --decoy-max 12 \
  --junk-frames 2 &
CL_PID=$!
sleep 1
curl -fsS --connect-timeout 8 --max-time 20 --socks5-hostname 127.0.0.1:11081 http://example.com/ -o "$BODY"
head -c 60 "$BODY"
echo
echo "OK: wsl tests passed (proto 3, with/without decoy)."
