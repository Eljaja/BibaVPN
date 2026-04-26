#!/usr/bin/env bash
# UDP over SOCKS5 → bibavpn UDP mux → local echo. Run from WSL, repo root.
set -u
cd "$(dirname "$0")/.." || exit 1
cargo build -p bibavpn --release -q
BIN=target/release
EPORT=19998
RUST_LOG=warn

python3 -c "import socks" 2>/dev/null || python3 -m pip install --user --break-system-packages pysocks -q

cleanup() {
  kill "${EPID:-}" 2>/dev/null || true
  kill "${SPID:-}" 2>/dev/null || true
  kill "${CPID:-}" 2>/dev/null || true
}
trap cleanup EXIT

# UDP echo (recv — echo back)
export BENCH_UDP_PORT="$EPORT"
python3 -u - <<'PY' &
import os, socket
port = int(os.environ["BENCH_UDP_PORT"])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", port))
while True:
    d, a = s.recvfrom(65535)
    s.sendto(d, a)
PY
EPID=$!

"$BIN/bibavpn-server" \
  --listen 127.0.0.1:18444 \
  --self-signed-san localhost \
  --token benchudp \
  --psk benchpsk \
  --proto-domain localhost \
  --ws-ping-secs 0 >/tmp/bibavpn-server-udp.log 2>&1 &
SPID=$!
sleep 0.6
"$BIN/bibavpn-client" \
  --server 127.0.0.1:18444 \
  --sni localhost \
  --token benchudp \
  --psk benchpsk \
  --proto-domain localhost \
  --insecure \
  --socks5 127.0.0.1:11081 \
  --ws-ping-secs 0 \
  --udp-mux-reply-timeout-secs 5 >/tmp/bibavpn-client-udp.log 2>&1 &
CPID=$!
sleep 2

python3 -u - <<PY
import socket, socks, time, sys

SIZE = 1200
ROUNDS = 2000
PROXY_PORT = 11081
ECHO = ("127.0.0.1", $EPORT)

s = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)
s.set_proxy(socks.SOCKS5, "127.0.0.1", PROXY_PORT)
s.settimeout(4.0)
payload = b"x" * SIZE

# Direct UDP (no SOCKS) — localhost baseline
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.settimeout(2.0)
t0 = time.perf_counter()
ok = 0
for i in range(ROUNDS):
    u.sendto(payload, ECHO)
    u.recvfrom(65535)
    ok += 1
dt = time.perf_counter() - t0
mbps = (ok * SIZE * 8) / dt / 1e6
print(f"=== Direct UDP echo (no SOCKS), {ROUNDS}x{SIZE} B ===")
print(f"rounds={ok} time={dt:.3f}s  throughput={mbps:.1f} Mbit/s  (app-level, RTT-bound)")

t0 = time.perf_counter()
ok = 0
for i in range(ROUNDS):
    s.sendto(payload, ECHO)
    s.recvfrom(65535)
    ok += 1
dt = time.perf_counter() - t0
mbps = (ok * SIZE * 8) / dt / 1e6
print(f"=== Via SOCKS5 + Biba UDP mux, {ROUNDS}x{SIZE} B ===")
print(f"rounds={ok} time={dt:.3f}s  throughput={mbps:.1f} Mbit/s  (app-level, RTT-bound)")
PY

echo "Done."
