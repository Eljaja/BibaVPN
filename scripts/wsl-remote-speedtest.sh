#!/usr/bin/env bash
# Start 64 MiB file + python http on VPS (BIBA_HOST), then bench from WSL through bibavpn-client.
# Usage: BIBA_HOST=202.181.159.79 bash scripts/wsl-remote-speedtest.sh
set -euo pipefail
: "${BIBA_HOST:?BIBA_HOST}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
cargo build -p bibavpn --release -q
BIN=target/release/bibavpn-client
SOCK=127.0.0.1:11096
# Match docker deploy (v3, default proto-domain) — set BIBA_TOKEN BIBA_PSK or edit here after inspect
: "${BIBA_TOKEN:?BIBA_TOKEN}"
: "${BIBA_PSK:?BIBA_PSK}"
REMOTE_STUFF="$(ssh -o ConnectTimeout=20 "root@${BIBA_HOST}" 'bash -s' <<'REMOTE'
set -euo pipefail
pkill -f "http.server 19999" 2>/dev/null || true
sleep 0.3
dd if=/dev/zero of=/tmp/bibavpn-bench.bin bs=1M count=64 status=none
cd /tmp
nohup python3 -m http.server 19999 --bind 0.0.0.0 >/tmp/httpserver-bench.log 2>&1 &
echo $! > /tmp/bench_hpid
sleep 1
ss -lntp | grep -E ':19999\s' || { echo "port 19999 not listening" >&2; cat /tmp/httpserver-bench.log >&2; exit 1; }
echo "remote_http_ok"
REMOTE
)"
echo "$REMOTE_STUFF"
RUST_LOG=warn "$BIN" \
  --server "${BIBA_HOST}:8443" \
  --sni "${BIBA_HOST}" \
  --token "$BIBA_TOKEN" \
  --psk "$BIBA_PSK" \
  --proto 3 \
  --proto-domain default \
  --insecure \
  --socks5 "$SOCK" \
  --decoy-max 32 \
  --max-pad 64 \
  --max-ws-binary 1400 \
  --ws-ping-secs 25 \
  >/tmp/bibavpn-client-bench.log 2>&1 &
CL_PID=$!
for _ in $(seq 1 40); do
  if (echo >/dev/tcp/127.0.0.1/11096) 2>/dev/null; then break; fi
  sleep 0.2
  if ! kill -0 "$CL_PID" 2>/dev/null; then
    echo "client died:" >&2
    cat /tmp/bibavpn-client-bench.log >&2
    exit 1
  fi
done
sleep 3

echo ""
echo "=== Direct HTTP, 64 MiB (WSL -> ${BIBA_HOST}, no Biba) ==="
curl -sS -o /dev/null -w "speed_bytes_sec=%{speed_download}  time_s=%{time_total}  size=%{size_download}\n" \
  --connect-timeout 30 --max-time 600 \
  "http://${BIBA_HOST}:19999/bibavpn-bench.bin"

echo "=== Via Biba SOCKS5 + WSS, 64 MiB (same URL) ==="
curl -sS -o /dev/null -w "speed_bytes_sec=%{speed_download}  time_s=%{time_total}  size=%{size_download}\n" \
  --connect-timeout 30 --max-time 600 \
  --proxy "socks5h://${SOCK}" \
  "http://${BIBA_HOST}:19999/bibavpn-bench.bin"

echo ""
echo "Done. (curl speed_download = bytes/s mean throughput over the transfer.)"
kill "$CL_PID" 2>/dev/null || true
wait "$CL_PID" 2>/dev/null || true
ssh "root@${BIBA_HOST}" 'kill $(cat /tmp/bench_hpid) 2>/dev/null; rm -f /tmp/bibavpn-bench.bin /tmp/bench_hpid; true'
