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
case "$RESOLVED" in
  *262144*) ;;
  *) echo "FAIL: 262144 not in config" >&2; exit 1 ;;
esac
case "$RESOLVED" in
  *print-invite-uri*) ;;
  *) echo "FAIL: print-invite-uri missing" >&2; exit 1 ;;
esac
case "$RESOLVED" in
  *invite-passphrase*) ;;
  *) echo "FAIL: invite-passphrase missing" >&2; exit 1 ;;
esac

echo "=== build ==="
docker compose --env-file "$ENV_FILE" -f docker-compose.yml build biba-server

echo "=== up -d ==="
docker compose --env-file "$ENV_FILE" -f docker-compose.yml up -d biba-server
trap 'docker compose --env-file "$ENV_FILE" -f docker-compose.yml down >/dev/null 2>&1 || true' EXIT
sleep 4
echo "=== logs (expect a biba:// line) ==="
# Capture once: `logs | grep -m1` can SIGPIPE the producer, and with
# `set -o pipefail` that turns a successful match into a failed pipeline.
LOGS="$(docker compose --env-file "$ENV_FILE" -f docker-compose.yml logs biba-server 2>&1 || true)"
printf '%s\n' "$LOGS" | tail -25
if [[ "$LOGS" =~ (biba://[^[:space:]]+) ]]; then
  INVITE_LINE="${BASH_REMATCH[1]}"
else
  echo "FAIL: no biba:// line in logs" >&2
  exit 1
fi

echo "=== OK ==="
printf '%s\n' "$INVITE_LINE"

echo "=== down ==="
docker compose --env-file "$ENV_FILE" -f docker-compose.yml down
trap - EXIT

echo "verify-compose-wsl.sh: all checks passed"
