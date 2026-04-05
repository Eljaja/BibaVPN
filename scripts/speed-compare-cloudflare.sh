#!/usr/bin/env bash
set -euo pipefail
# ~50 MiB from Cloudflare
URL='https://speed.cloudflare.com/__down?bytes=52428800'
SOCKS="${SOCKS:-127.0.0.1:11090}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SERVERTXT="${BIBA_SERVER_TXT:-$ROOT/../server.txt}"

echo "=== Local via SOCKS $SOCKS ==="
curl -fsS -o /dev/null --connect-timeout 30 --max-time 420 \
  -w "bytes=%{size_download} time_s=%{time_total} avg_Bps=%{speed_download}\n" \
  --socks5-hostname "$SOCKS" "$URL"

PASS="$(sed -n '6p' "$SERVERTXT" | tr -d '\r')"
HOST="$(sed -n '2p' "$SERVERTXT" | tr -d '\r')"
PORT="$(sed -n '8p' "$SERVERTXT" | tr -d '\r')"
export SSHPASS="$PASS"

echo "=== VPS $HOST direct (curl on server) ==="
# shellcheck disable=SC2029
sshpass -e ssh -p "$PORT" -o StrictHostKeyChecking=accept-new "root@$HOST" \
  "curl -fsS -o /dev/null --connect-timeout 30 --max-time 420 -w 'bytes=%{size_download} time_s=%{time_total} avg_Bps=%{speed_download}\n' '$URL'"

echo "Mbit/s ≈ avg_Bps * 8 / 1e6"
