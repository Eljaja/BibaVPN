#!/usr/bin/env bash
# Verify docker-compose + invite. Run from WSL at repo root:
#   bash scripts/verify-compose-wsl.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
ENV_FILE="${ROOT}/.biba-start.env"

BIBA_TOKEN="$(openssl rand -hex 16)"
BIBA_PSK="$(openssl rand -hex 16)"
BIBA_MAX_WS_BINARY=262144
BIBA_INVITE_PASSPHRASE="$(openssl rand -hex 24)"
BIBA_INVITE_PUBLIC=127.0.0.1:8443
BIBA_INVITE_SNI=biba-server

umask 077
{
  printf 'BIBA_TOKEN=%s\n' "$BIBA_TOKEN"
  printf 'BIBA_PSK=%s\n' "$BIBA_PSK"
  printf 'BIBA_MAX_WS_BINARY=%s\n' "$BIBA_MAX_WS_BINARY"
  printf 'BIBA_INVITE_PASSPHRASE=%s\n' "$BIBA_INVITE_PASSPHRASE"
  printf 'BIBA_INVITE_PUBLIC=%s\n' "$BIBA_INVITE_PUBLIC"
  printf 'BIBA_INVITE_SNI=%s\n' "$BIBA_INVITE_SNI"
} >"$ENV_FILE"

echo "=== compose config: 262144 + print-invite-uri ==="
RESOLVED="$(docker compose --env-file "$ENV_FILE" -f docker-compose.yml config)"
echo "$RESOLVED" | grep -q '262144' || { echo "FAIL: 262144 not in config" >&2; exit 1; }
echo "$RESOLVED" | grep -q 'print-invite-uri' || { echo "FAIL: print-invite-uri missing" >&2; exit 1; }
echo "$RESOLVED" | grep -q 'invite-passphrase' || { echo "FAIL: invite-passphrase missing" >&2; exit 1; }

echo "=== build ==="
docker compose --env-file "$ENV_FILE" -f docker-compose.yml build biba-server

echo "=== up -d ==="
docker compose --env-file "$ENV_FILE" -f docker-compose.yml up -d biba-server
sleep 4
echo "=== logs (expect a biba:// line) ==="
docker compose --env-file "$ENV_FILE" -f docker-compose.yml logs biba-server 2>&1 | tail -25

if ! docker compose --env-file "$ENV_FILE" -f docker-compose.yml logs biba-server 2>&1 | grep -q 'biba://'; then
  echo "FAIL: no biba:// line in logs" >&2
  exit 1
fi

echo "=== OK ==="
docker compose --env-file "$ENV_FILE" -f docker-compose.yml logs biba-server 2>&1 | grep 'biba://' | head -n1

echo "=== down ==="
docker compose --env-file "$ENV_FILE" -f docker-compose.yml down

echo "verify-compose-wsl.sh: all checks passed"
