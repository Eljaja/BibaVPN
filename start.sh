#!/usr/bin/env bash
# One-shot local server: secrets, invite, max-ws-binary 262144, docker compose up -d.
# Optional before run: BIBA_INVITE_PUBLIC, BIBA_INVITE_SNI, BIBA_INVITE_PASSPHRASE, BIBA_MAX_WS_BINARY
# Run: bash start.sh   (or: bash start.sh --build)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

ENV_FILE="${ROOT}/.biba-start.env"

BIBA_INVITE_PUBLIC="${BIBA_INVITE_PUBLIC:-127.0.0.1:8443}"
BIBA_INVITE_SNI="${BIBA_INVITE_SNI:-biba-server}"
BIBA_MAX_WS_BINARY="${BIBA_MAX_WS_BINARY:-262144}"

BIBA_TOKEN="$(openssl rand -hex 16)"
BIBA_PSK="$(openssl rand -hex 16)"
if [[ -z "${BIBA_INVITE_PASSPHRASE:-}" ]]; then
  BIBA_INVITE_PASSPHRASE="$(openssl rand -hex 24)"
fi

export BIBA_TOKEN BIBA_PSK BIBA_MAX_WS_BINARY BIBA_INVITE_PASSPHRASE BIBA_INVITE_PUBLIC BIBA_INVITE_SNI

umask 077
{
  printf 'BIBA_TOKEN=%s\n' "$BIBA_TOKEN"
  printf 'BIBA_PSK=%s\n' "$BIBA_PSK"
  printf 'BIBA_MAX_WS_BINARY=%s\n' "$BIBA_MAX_WS_BINARY"
  printf 'BIBA_INVITE_PASSPHRASE=%s\n' "$BIBA_INVITE_PASSPHRASE"
  printf 'BIBA_INVITE_PUBLIC=%s\n' "$BIBA_INVITE_PUBLIC"
  printf 'BIBA_INVITE_SNI=%s\n' "$BIBA_INVITE_SNI"
} >"$ENV_FILE"

echo "Values saved to $ENV_FILE (do not commit)" >&2
echo "Connect: ${BIBA_INVITE_PUBLIC} (SNI: ${BIBA_INVITE_SNI})" >&2
echo "Starting biba-server (docker compose up -d)..." >&2
docker compose --env-file "$ENV_FILE" -f docker-compose.yml up -d "$@" biba-server

INVITE_URI=""
i=0
while [[ $i -lt 90 ]]; do
  log="$(docker compose --env-file "$ENV_FILE" -f docker-compose.yml logs --no-color --tail=200 biba-server 2>&1 || true)"
  if [[ "$log" =~ (biba://[^[:space:]]+) ]]; then
    INVITE_URI="${BASH_REMATCH[1]}"
    break
  fi
  sleep 1
  i=$((i + 1))
done

if [[ -z "$INVITE_URI" ]]; then
  echo "start.sh: invite URI not found in logs yet (docker compose ... logs biba-server | grep biba://)" >&2
fi

echo ""
echo "Invite URI — encrypted one-line config for the client (paste this as the biba:// key / invite field):"
echo "$INVITE_URI"
echo ""
echo "Passphrase — secret key that decrypts the URI; share it only out-of-band, never bundled with the URI in chat or tickets:"
echo "$BIBA_INVITE_PASSPHRASE"
echo ""
