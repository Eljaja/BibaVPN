#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
SRV="${ROOT}/target/release/bibavpn-server"
CL="${ROOT}/target/release/bibavpn-client"
CERT=/tmp/biba_v3_test.crt
KEY=/tmp/biba_v3_test.key
openssl req -x509 -newkey rsa:2048 -keyout "$KEY" -out "$CERT" -days 1 -nodes -subj "/CN=localhost" 2>/dev/null

cleanup() {
  kill "${HP:-}" "${CP:-}" "${SP:-}" "${H2:-}" "${C2:-}" "${S2:-}" 2>/dev/null || true
}
trap cleanup EXIT

# --- v3 ---
PORT=18650
SOCK=11650
HTTP=28650
fuser -k "${PORT}/tcp" 2>/dev/null || true
fuser -k "${SOCK}/tcp" 2>/dev/null || true
sleep 0.2
RUST_LOG=warn "$SRV" --listen "127.0.0.1:${PORT}" --cert "$CERT" --key "$KEY" --token t --psk secretpsk --proto-domain labv3 --ws-path /ws &
SP=$!
sleep 0.8
RUST_LOG=warn "$CL" --server "127.0.0.1:${PORT}" --sni localhost --token t --psk secretpsk --proto 3 --proto-domain labv3 --socks5 "127.0.0.1:${SOCK}" --ws-path /ws --pin-cert "$CERT" --tls-profile chrome70 &
CP=$!
sleep 1.2
echo ok > /tmp/biba_v3_beh.txt
python3 -m http.server "$HTTP" --directory /tmp >/tmp/biba_v3_http.log 2>&1 &
HP=$!
sleep 0.4
curl -fsS -o /dev/null --max-time 15 --socks5-hostname "127.0.0.1:${SOCK}" "http://127.0.0.1:${HTTP}/biba_v3_beh.txt"
echo "v3 curl OK"
kill "$HP" "$CP" "$SP" 2>/dev/null || true
wait 2>/dev/null || true

# --- v2 backward ---
PORT2=18651
SOCK2=11651
HTTP2=28651
fuser -k "${PORT2}/tcp" 2>/dev/null || true
fuser -k "${SOCK2}/tcp" 2>/dev/null || true
sleep 0.2
RUST_LOG=warn "$SRV" --listen "127.0.0.1:${PORT2}" --cert "$CERT" --key "$KEY" --token t --psk secretpsk --ws-path /ws &
S2=$!
sleep 0.8
RUST_LOG=warn "$CL" --server "127.0.0.1:${PORT2}" --sni localhost --token t --psk secretpsk --socks5 "127.0.0.1:${SOCK2}" --ws-path /ws --pin-cert "$CERT" --tls-profile chrome70 &
C2=$!
sleep 1.2
python3 -m http.server "$HTTP2" --directory /tmp >/tmp/biba_v2_http.log 2>&1 &
H2=$!
sleep 0.4
curl -fsS -o /dev/null --max-time 15 --socks5-hostname "127.0.0.1:${SOCK2}" "http://127.0.0.1:${HTTP2}/biba_v3_beh.txt"
echo "v2 curl OK"
