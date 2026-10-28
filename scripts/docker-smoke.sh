#!/usr/bin/env bash
# Local compose e2e: SOCKS5 + HTTP CONNECT through the tunnel.
# Leaves no containers behind on failure (EXIT trap); captures bodies to a temp
# file instead of `curl | head`, which would trip `set -o pipefail` on SIGPIPE.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BODY="$(mktemp)"
cleanup() {
  rm -f "$BODY"
  docker compose down >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker compose down >/dev/null 2>&1 || true
docker compose up --build -d

# Wait for the published client ports instead of a fixed sleep; a cold
# `--build` on a small VPS boots slower than 3 s.
for port in 11080 11880; do
  for _ in $(seq 1 60); do
    if (echo >"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; then
      break
    fi
    sleep 1
  done
  if ! (echo >"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; then
    echo "docker-smoke: client port ${port} did not open" >&2
    docker compose logs --tail 100 >&2 || true
    exit 1
  fi
done

echo "--- curl via docker client SOCKS5 (BibaV2 PSK) ---"
curl -fsS --max-time 30 --socks5-hostname 127.0.0.1:11080 http://example.com/ -o "$BODY"
head -c 120 "$BODY"
echo
echo "--- curl via HTTP CONNECT proxy localhost:11880 ---"
curl -fsS --max-time 30 --proxy http://127.0.0.1:11880 https://example.com/ -o "$BODY"
head -c 120 "$BODY"
echo
echo "OK: docker compose smoke passed."
