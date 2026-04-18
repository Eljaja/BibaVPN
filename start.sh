#!/usr/bin/env bash
# One-shot local server: secrets, invite, max-ws-binary 262144, docker compose up.
# Optional before run: BIBA_INVITE_PUBLIC, BIBA_INVITE_SNI, BIBA_INVITE_PASSPHRASE, BIBA_MAX_WS_BINARY
# Pass -d / --detach to exit after printing the invite (containers keep running).
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

detach_user=false
compose_args=()
for a in "$@"; do
  if [[ "$a" == "-d" || "$a" == "--detach" ]]; then
    detach_user=true
  else
    compose_args+=("$a")
  fi
done

echo ""
echo "════════════════════════════════════════════════════════════"
echo " Biba VPN — starting biba-server (docker compose)"
echo "════════════════════════════════════════════════════════════"
echo " Values saved to: $ENV_FILE (do not commit)"
echo ""
echo " Connect from host: ${BIBA_INVITE_PUBLIC}  (SNI: ${BIBA_INVITE_SNI}, --insecure for self-signed)"
echo "════════════════════════════════════════════════════════════"
echo ""

echo "Starting biba-server (detached)..."
docker compose --env-file "$ENV_FILE" -f docker-compose.yml up -d "${compose_args[@]}" biba-server

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

echo ""
echo " ── Invite passphrase (give to clients together with the URI below):"
echo "    ${BIBA_INVITE_PASSPHRASE}"
echo ""
if [[ -n "$INVITE_URI" ]]; then
  echo " ── Invite URI:"
  echo "    ${INVITE_URI}"
else
  echo " ── Invite URI: (not in logs yet — check: docker compose --env-file \"$ENV_FILE\" -f docker-compose.yml logs biba-server | grep biba://)" >&2
fi
echo ""
echo " Client:  --from-invite 'biba://…'  --invite-passphrase '…'"
echo " (or paste key + passphrase in Android / desktop UI)"
echo "════════════════════════════════════════════════════════════"
echo ""

if [[ "$detach_user" == "true" ]]; then
  exit 0
fi

echo "Following server logs (^C stops following only; use: docker compose --env-file \"$ENV_FILE\" -f docker-compose.yml down)"
docker compose --env-file "$ENV_FILE" -f docker-compose.yml logs -f biba-server
