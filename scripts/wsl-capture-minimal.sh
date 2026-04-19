#!/usr/bin/env bash
# Minimal: debug order + tcpdump on loopback (isolates tcpdump interaction).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PORT="${1:-18465}"
SOCK="${2:-11105}"
PCAP="/tmp/biba_min_${PORT}.pcap"
CERT_DIR="/tmp/biba_capture_certs"
CERT="${CERT_DIR}/localhost-${PORT}.crt"
KEY="${CERT_DIR}/localhost-${PORT}.key"
HTTP_PORT=$((PORT + 10000))

fuser -k "${PORT}/tcp" 2>/dev/null || true
fuser -k "${SOCK}/tcp" 2>/dev/null || true
sleep 0.2

mkdir -p "$CERT_DIR"
if [[ ! -f "$CERT" ]]; then
  openssl req -x509 -newkey rsa:2048 -keyout "$KEY" -out "$CERT" -days 2 -nodes -subj "/CN=localhost"
fi

rm -f "$PCAP"
tcpdump -i any -w "$PCAP" "port ${PORT}" >/dev/null 2>&1 &
TP=$!

cleanup() {
  kill "${HPID:-}" "${CP:-}" "${SP:-}" 2>/dev/null || true
  sleep 0.2
  kill "${TP:-}" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT
sleep 0.3

RUST_LOG=warn "${ROOT}/target/release/bibavpn-server" \
  --listen "127.0.0.1:${PORT}" --cert "$CERT" --key "$KEY" --token t --ws-path /ws --ws-ping-secs 0 &
SP=$!
sleep 0.8

RUST_LOG=warn "${ROOT}/target/release/bibavpn-client" \
  --server "127.0.0.1:${PORT}" --sni localhost --token t --socks5 "127.0.0.1:${SOCK}" \
  --ws-path /ws --tls-profile chrome70 --pin-cert "$CERT" &
CP=$!
sleep 1
echo ok >"/tmp/biba-min.txt"
python3 -m http.server "${HTTP_PORT}" --directory /tmp >/tmp/biba-min-http.log 2>&1 &
HPID=$!
sleep 0.5
curl -fsS -o /dev/null --max-time 15 --socks5-hostname "127.0.0.1:${SOCK}" \
  "http://127.0.0.1:${HTTP_PORT}/biba-min.txt"
sleep 0.3

cleanup
trap - EXIT

echo "--- pcap $PCAP ---"
python3 "${ROOT}/scripts/wsl-pcap-tls-dump.py" "$PCAP" "$PORT"
