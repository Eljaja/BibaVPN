#!/usr/bin/env bash
# 64 MiB local bench: "max stealth" (aggressive preset + 4x WSS + server ACK profile + padding/decoy/jitter).
#
# Outer TLS (client only):
#   Default: rustls (fast build, same as typical deploy).
#   Optional: BIBAVPN_BENCH_TLS=boring  →  cargo --features boring-tls, client --tls-stack boring
#   (boring-sys can take minutes to build; use only when you need to measure Boring.)
#
# Other env:
#   BIBAVPN_BENCH_SKIP_BUILD=1  — do not run cargo (reuse existing target/release binaries)
#
# Run from repo root:  bash scripts/wsl-max-stealth-bench.sh
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="${HOME}/.cargo/bin:${PATH}"

TLS_MODE="${BIBAVPN_BENCH_TLS:-rustls}"
CURL_MAX="${BIBAVPN_BENCH_CURL_MAX_TIME:-120}"
CURL_CONN="${BIBAVPN_BENCH_CURL_CONNECT:-20}"

echo "[bench] TLS stack: ${TLS_MODE}  (set BIBAVPN_BENCH_TLS=boring for BoringSSL)"
echo "[bench] curl limits: connect ${CURL_CONN}s, total ${CURL_MAX}s per transfer"

if [[ "${BIBAVPN_BENCH_SKIP_BUILD:-0}" == 1 ]]; then
  echo "[bench] SKIP_BUILD=1 — using existing target/release"
else
  echo "[bench] cargo build --release …"
  if [[ "$TLS_MODE" == boring ]]; then
    cargo build -p bibavpn --release --features boring-tls
  else
    cargo build -p bibavpn --release
  fi
  echo "[bench] build done"
fi

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

echo "[bench] starting bibavpn-server…"
RUST_LOG=warn "$BIN/bibavpn-server" \
  --listen 127.0.0.1:18443 \
  --self-signed-san localhost \
  --token benchtest \
  --psk benchpsk \
  --proto-domain localhost \
  --ws-ping-secs 0 \
  --pad-mode adaptive \
  --max-pad 64 \
  --decoy-max 32 \
  --ack-profile aggressive \
  --ws-jitter-min-ms 5 \
  --ws-jitter-max-ms 25 \
  --dummy-interval-secs 45 \
  >/tmp/bibavpn-server.log 2>&1 &
SPID=$!
sleep 0.8

CLIENT_EXTRA=()
if [[ "$TLS_MODE" == boring ]]; then
  CLIENT_EXTRA+=(--tls-stack boring)
fi

echo "[bench] starting bibavpn-client…"
RUST_LOG=warn "$BIN/bibavpn-client" \
  --server 127.0.0.1:18443 \
  --sni localhost \
  --token benchtest \
  --psk benchpsk \
  --proto-domain localhost \
  --insecure \
  --socks5 127.0.0.1:11080 \
  --ws-ping-secs 0 \
  --stealth-profile aggressive \
  --ws-parallel 4 \
  --max-pad 64 \
  --decoy-max 32 \
  --tls-fragment \
  "${CLIENT_EXTRA[@]}" \
  --decoy-mode browser \
  >/tmp/bibavpn-client.log 2>&1 &
CPID=$!

# Wait until SOCKS listens (avoids curl hanging forever if the client failed).
echo "[bench] waiting for SOCKS :11080 …"
ok=0
for _ in $(seq 1 100); do
  if ! kill -0 "$CPID" 2>/dev/null; then
    echo "[bench] client process died; tail bibavpn-client.log:"
    tail -80 /tmp/bibavpn-client.log || true
    exit 1
  fi
  if command -v nc >/dev/null 2>&1; then
    if nc -z 127.0.0.1 11080 2>/dev/null; then
      ok=1
      break
    fi
  elif timeout 0.3 bash -c "echo > /dev/tcp/127.0.0.1/11080" 2>/dev/null; then
    ok=1
    break
  fi
  sleep 0.2
done
if [[ "$ok" != 1 ]]; then
  echo "[bench] timeout waiting for SOCKS (~20s). Client log:"
  tail -80 /tmp/bibavpn-client.log || true
  exit 1
fi
echo "[bench] SOCKS up, running curl …"

DESCR="Biba max-stealth: aggressive, ws-parallel=4, ack-profile aggressive, adaptive pad, tls-fragment, jitter, dummy 45s."
if [[ "$TLS_MODE" == boring ]]; then
  DESCR="${DESCR} Client outer TLS: BoringSSL. Server: rustls."
else
  DESCR="${DESCR} Client outer TLS: rustls (default)."
fi

{
  echo "$DESCR"
  echo ""
  echo "=== Direct HTTP (no tunnel), 64 MiB ==="
  curl -sS -o /dev/null \
    --connect-timeout "$CURL_CONN" \
    --max-time "$CURL_MAX" \
    -w "speed_download=%{speed_download} B/s  time_total=%{time_total}s\n" \
    http://127.0.0.1:18080/bibavpn-bench.bin
  echo "=== Via Biba SOCKS5 + WSS, 64 MiB ==="
  curl -sS -o /dev/null \
    --connect-timeout "$CURL_CONN" \
    --max-time "$CURL_MAX" \
    -w "speed_download=%{speed_download} B/s  time_total=%{time_total}s\n" \
    --proxy socks5h://127.0.0.1:11080 http://127.0.0.1:18080/bibavpn-bench.bin
  echo "Done."
} | tee /tmp/bibavpn-max-stealth-bench.txt

cat /tmp/bibavpn-max-stealth-bench.txt
