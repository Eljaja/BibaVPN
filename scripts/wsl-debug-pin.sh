#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PORT="${1:-18452}"
SOCK="${2:-11097}"
CERT_DIR="/tmp/biba_capture_certs"
CERT="${CERT_DIR}/localhost-${PORT}.crt"
KEY="${CERT_DIR}/localhost-${PORT}.key"
mkdir -p "$CERT_DIR"
if [[ ! -f "$CERT" ]]; then
  openssl req -x509 -newkey rsa:2048 -keyout "$KEY" -out "$CERT" -days 2 -nodes -subj "/CN=localhost"
fi
RUST_LOG=info "${ROOT}/target/release/bibavpn-server" \
  --listen "127.0.0.1:${PORT}" --cert "$CERT" --key "$KEY" --token t --ws-path /ws --ws-ping-secs 0 &
SP=$!
sleep 0.8
RUST_LOG=info "${ROOT}/target/release/bibavpn-client" \
  --server "127.0.0.1:${PORT}" --sni localhost --token t --socks5 "127.0.0.1:${SOCK}" \
  --ws-path /ws --tls-profile chrome70 --pin-cert "$CERT" &
CP=$!
sleep 1
echo ok >/tmp/biba-dbg.txt
python3 -m http.server $((PORT+10000)) --directory /tmp >/tmp/biba-dbg-http.log 2>&1 &
HP=$!
sleep 0.5
curl -v --max-time 10 --socks5-hostname "127.0.0.1:${SOCK}" "http://127.0.0.1:$((PORT+10000))/biba-dbg.txt" || true
sleep 1
kill "$HP" 2>/dev/null || true
kill "$CP" "$SP" 2>/dev/null || true
wait 2>/dev/null || true
