#!/usr/bin/env bash
# Compare: direct download on the VPS vs via bibavpn SOCKS on this machine.
set -euo pipefail
URL="${1:-https://proof.ovh.net/files/50Mb.dat}"
SOCKS="${SOCKS:-127.0.0.1:11090}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SERVERTXT="${BIBA_SERVER_TXT:-$ROOT/../server.txt}"

run_curl() {
  local label=$1
  shift
  echo "=== $label ==="
  curl -fsS -o /dev/null --connect-timeout 25 --max-time 300 \
    -w "bytes=%{size_download} time_s=%{time_total} avg_bytes_per_sec=%{speed_download}\n" \
    "$@" "$URL"
  echo
}

run_curl "Local via SOCKS $SOCKS" --socks5-hostname "$SOCKS"

PASS="$(sed -n '6p' "$SERVERTXT" | tr -d '\r')"
HOST="$(sed -n '2p' "$SERVERTXT" | tr -d '\r')"
PORT="$(sed -n '8p' "$SERVERTXT" | tr -d '\r')"
export SSHPASS="$PASS"

echo "=== VPS $HOST direct (curl on server) ==="
sshpass -e ssh -p "$PORT" -o StrictHostKeyChecking=accept-new "root@$HOST" \
  "curl -fsS -o /dev/null --connect-timeout 25 --max-time 300 \
    -w 'bytes=%{size_download} time_s=%{time_total} avg_bytes_per_sec=%{speed_download}\n' \
    '$URL'"

echo
echo "Hint: Mbit/s ≈ avg_bytes_per_sec * 8 / 1e6"
