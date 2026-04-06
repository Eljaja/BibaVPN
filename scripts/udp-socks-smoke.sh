#!/usr/bin/env bash
# Local TCP + UDP SOCKS smoke (needs built debug binaries, PySocks, internet for DNS).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export RUST_LOG="${RUST_LOG:-warn}"

pick_port() {
  /usr/bin/python3 -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1])"
}

SRV_PORT="${SRV_PORT:-$(pick_port)}"
SOCK_PORT="${SOCK_PORT:-$(pick_port)}"
SRV_LOG="$(mktemp)"
CL_LOG="$(mktemp)"

cleanup() {
  kill "${CL_PID:-}" "${SRV_PID:-}" 2>/dev/null || true
  rm -f "${SRV_LOG}" "${CL_LOG}"
}
trap cleanup EXIT

./target/debug/bibavpn-server \
  --listen "127.0.0.1:${SRV_PORT}" \
  --self-signed-san localhost \
  --token testtok \
  --psk testpsk \
  --decoy-max 8 \
  --max-pad 16 \
  --max-ws-binary 2048 >"${SRV_LOG}" 2>&1 &
SRV_PID=$!

for _ in $(seq 1 40); do
  if ! kill -0 "${SRV_PID}" 2>/dev/null; then
    echo "bibavpn-server exited early:" >&2
    cat "${SRV_LOG}" >&2
    exit 1
  fi
  if (echo >/dev/tcp/127.0.0.1/"${SRV_PORT}") 2>/dev/null; then
    break
  fi
  sleep 0.1
done

if ! (echo >/dev/tcp/127.0.0.1/"${SRV_PORT}") 2>/dev/null; then
  echo "server not listening on ${SRV_PORT}" >&2
  cat "${SRV_LOG}" >&2
  exit 1
fi

./target/debug/bibavpn-client \
  --server "127.0.0.1:${SRV_PORT}" \
  --sni localhost \
  --token testtok \
  --insecure \
  --socks5 "127.0.0.1:${SOCK_PORT}" \
  --psk testpsk \
  --decoy-max 8 \
  --max-pad 16 \
  --max-ws-binary 2048 >"${CL_LOG}" 2>&1 &
CL_PID=$!

for _ in $(seq 1 40); do
  if ! kill -0 "${CL_PID}" 2>/dev/null; then
    echo "bibavpn-client exited early:" >&2
    cat "${CL_LOG}" >&2
    exit 1
  fi
  if (echo >/dev/tcp/127.0.0.1/"${SOCK_PORT}") 2>/dev/null; then
    break
  fi
  sleep 0.1
done

if ! (echo >/dev/tcp/127.0.0.1/"${SOCK_PORT}") 2>/dev/null; then
  echo "SOCKS not listening on ${SOCK_PORT}" >&2
  cat "${CL_LOG}" >&2
  exit 1
fi

echo "--- TCP via SOCKS (server ${SRV_PORT}, socks ${SOCK_PORT}) ---"
curl -fsS -o /dev/null -w "http example.com %{http_code}\n" \
  --connect-timeout 15 \
  --socks5-hostname "127.0.0.1:${SOCK_PORT}" \
  http://example.com/

echo "--- UDP DNS via SOCKS (8.8.8.8:53) ---"
/usr/bin/python3 - "$SOCK_PORT" << 'PY'
import socket, socks, sys
port = int(sys.argv[1])
q = bytes.fromhex("1234010000010000000000076578616d706c6503636f6d0000010001")
sock = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)
sock.set_proxy(socks.SOCKS5, "127.0.0.1", port)
sock.settimeout(20)
sock.sendto(q, ("8.8.8.8", 53))
r, _ = sock.recvfrom(4096)
assert len(r) >= 12, f"short DNS reply: {len(r)}"
print("dns_reply_len", len(r))
PY

echo "OK udp-socks-smoke"
