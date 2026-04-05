#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

cargo build --message-format=short
SERVER_BIN="$ROOT/target/debug/bibavpn-server"
CLIENT_BIN="$ROOT/target/debug/bibavpn-client"

cleanup() {
  kill "${SRV_PID:-}" "${CL_PID:-}" 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Plain mode (no PSK) ==="
"$SERVER_BIN" --listen 127.0.0.1:18443 --self-signed-san localhost --token wsl-test-token &
SRV_PID=$!
sleep 1
"$CLIENT_BIN" \
  --server 127.0.0.1:18443 \
  --sni localhost \
  --token wsl-test-token \
  --insecure \
  --socks5 127.0.0.1:11080 \
  --junk-frames 1 &
CL_PID=$!
sleep 1
curl -fsS --connect-timeout 8 --socks5-hostname 127.0.0.1:11080 http://example.com/ | head -c 60
echo
cleanup
SRV_PID= CL_PID=
sleep 1

echo "=== BibaV2 PSK + decoy ==="
"$SERVER_BIN" \
  --listen 127.0.0.1:18444 \
  --self-signed-san localhost \
  --token wsl-v2 \
  --psk "wsl-secret-psk" \
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
  --psk "wsl-secret-psk" \
  --decoy-max 12 \
  --junk-frames 2 &
CL_PID=$!
sleep 1
curl -fsS --connect-timeout 8 --socks5-hostname 127.0.0.1:11081 http://example.com/ | head -c 60
echo
echo "OK: wsl tests passed (plain + PSK)."
