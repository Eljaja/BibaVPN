#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
docker compose down 2>/dev/null || true
docker compose up --build -d
sleep 3
echo "--- curl via docker client SOCKS5 (BibaV2 PSK) ---"
curl -fsS --connect-timeout 15 --socks5-hostname 127.0.0.1:11080 http://example.com/ | head -c 120
echo
echo "--- curl via HTTP CONNECT proxy localhost:11880 ---"
curl -fsS --connect-timeout 15 --proxy http://127.0.0.1:11880 https://example.com/ | head -c 120
echo
docker compose down
echo "OK: docker compose smoke passed."
