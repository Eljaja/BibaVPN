#!/usr/bin/env bash
# Local throughput: direct HTTP vs SOCKS5 through bibavpn (WSS). Run inside WSL from repo root.
set -u
cd "$(dirname "$0")/.." || exit 1
cargo build -p bibavpn --release -q
BIN=target/release
dd if=/dev/zero of=/tmp/bibavpn-bench.bin bs=1M count=64 status=none

python3 -m http.server 18080 --directory /tmp >/tmp/bibavpn-httpserver.log 2>&1 &
HPID=$!

cleanup() {
  kill "${HPID:-}" 2>/dev/null || true
  kill "${SPID:-}" 2>/dev/null || true
  kill "${CPID:-}" 2>/dev/null || true
}
trap cleanup EXIT

sleep 0.5
RUST_LOG=warn "$BIN/bibavpn-server" \
  --listen 127.0.0.1:18443 \
  --self-signed-san localhost \
  --token benchtest \
  --psk benchpsk \
  --proto-domain localhost \
  --ws-ping-secs 0 >/tmp/bibavpn-server.log 2>&1 &
SPID=$!
sleep 0.8
RUST_LOG=warn "$BIN/bibavpn-client" \
  --server 127.0.0.1:18443 \
  --sni localhost \
  --token benchtest \
  --psk benchpsk \
  --proto-domain localhost \
  --insecure \
  --socks5 127.0.0.1:11080 \
  --ws-ping-secs 0 >/tmp/bibavpn-client.log 2>&1 &
CPID=$!
sleep 2

echo "=== Direct HTTP (no tunnel), 64 MiB ==="
curl -sS -o /dev/null -w "speed_download=%{speed_download} B/s  time_total=%{time_total}s\n" \
  http://127.0.0.1:18080/bibavpn-bench.bin

echo "=== Via Biba SOCKS5 + WSS, 64 MiB ==="
curl -sS -o /dev/null -w "speed_download=%{speed_download} B/s  time_total=%{time_total}s\n" \
  --proxy socks5h://127.0.0.1:11080 http://127.0.0.1:18080/bibavpn-bench.bin

echo "Done."
