#!/usr/bin/env bash
# Start the server from prebuilt images; add --mesh to include Yggdrasil.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

ENV_FILE="${ROOT}/.biba-start.env"

mesh="${BIBA_YB_MESH:-0}"
for arg in "$@"; do
  case "$arg" in
    --mesh) mesh=1 ;;
    --no-mesh) mesh=0 ;;
    -h|--help) echo 'Usage: bash start.sh [--mesh|--no-mesh]'; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done
[[ "$mesh" == 0 || "$mesh" == 1 ]] || { echo 'BIBA_YB_MESH must be 0 or 1' >&2; exit 2; }

if [[ "$mesh" == 1 ]]; then
  BIBA_SERVER_IMAGE="${BIBA_SERVER_IMAGE:-eljaja/bibavpn-server:mesh}"
else
  BIBA_SERVER_IMAGE="${BIBA_SERVER_IMAGE:-eljaja/bibavpn-server:latest}"
fi
BIBA_MESH_IMAGE="${BIBA_MESH_IMAGE:-eljaja/bibavpn-yb-mesh:latest}"
export BIBA_SERVER_IMAGE BIBA_MESH_IMAGE
compose=(docker compose -f docker-compose.yml -f docker-compose.prebuilt.yml)

if [[ "$mesh" == 1 ]]; then
  # Mesh transports ignore the public host/port, so use a memorable DNS-like name
  # for the certificate SAN, SNI and the invite's display address. A random word
  # is easier to recognize in the imported profile than a hex suffix.
  mesh_words=(
    amber anchor arrow aspen badger bamboo beacon birch bison bloom brook cedar
    cliff cloud comet coral crane creek dawn delta drift eagle ember falcon fern
    field finch fjord flint forest fox frost garnet glacier grove harbor hawk
    hazel heron hill island ivy jade juniper kite lake larch lark lotus maple
    meadow mesa mist moon moss oak ocean olive orchid otter peak pine quail
    quartz rain raven reef ridge river robin rose sage sand shore sky snow
    sparrow spring spruce star stone storm stream sun swift thistle tide timber
    trail valley vine wave willow wind wolf wren
  )
  if [[ -z "${BIBA_INVITE_SNI:-}" ]]; then
    mesh_count=${#mesh_words[@]}
    BIBA_INVITE_SNI="biba-${mesh_words[RANDOM % mesh_count]}"
  fi
  BIBA_INVITE_PUBLIC="${BIBA_INVITE_PUBLIC:-${BIBA_INVITE_SNI}:8443}"
else
  BIBA_INVITE_PUBLIC="${BIBA_INVITE_PUBLIC:-127.0.0.1:8443}"
  BIBA_INVITE_SNI="${BIBA_INVITE_SNI:-biba-server}"
fi
BIBA_MAX_WS_BINARY="${BIBA_MAX_WS_BINARY:-262144}"

BIBA_TOKEN="$(openssl rand -hex 16)"
BIBA_PSK="$(openssl rand -hex 16)"
if [[ -z "${BIBA_INVITE_PASSPHRASE:-}" ]]; then
  BIBA_INVITE_PASSPHRASE="$(openssl rand -hex 24)"
fi

export BIBA_TOKEN BIBA_PSK BIBA_MAX_WS_BINARY BIBA_INVITE_PASSPHRASE BIBA_INVITE_PUBLIC BIBA_INVITE_SNI

echo "Downloading server image: $BIBA_SERVER_IMAGE" >&2
"${compose[@]}" pull biba-server >&2
BIBA_YB_MESH_ENDPOINT=""
if [[ "$mesh" == 1 ]]; then
  echo "Downloading mesh image: $BIBA_MESH_IMAGE" >&2
  "${compose[@]}" --profile yb-mesh pull yb-mesh-init >&2
  mesh_address="$("${compose[@]}" --profile yb-mesh run --pull never --rm -T --quiet yb-mesh-init init)"
  [[ "$mesh_address" =~ ^2[0-3][0-9a-fA-F:]+$ ]] || { echo 'Invalid mesh address from image' >&2; exit 1; }
  BIBA_YB_MESH_ENDPOINT="[${mesh_address}]:8443"
fi
export BIBA_YB_MESH_ENDPOINT

umask 077
{
  printf 'BIBA_TOKEN=%s\n' "$BIBA_TOKEN"
  printf 'BIBA_PSK=%s\n' "$BIBA_PSK"
  printf 'BIBA_MAX_WS_BINARY=%s\n' "$BIBA_MAX_WS_BINARY"
  printf 'BIBA_INVITE_PASSPHRASE=%s\n' "$BIBA_INVITE_PASSPHRASE"
  printf 'BIBA_INVITE_PUBLIC=%s\n' "$BIBA_INVITE_PUBLIC"
  printf 'BIBA_INVITE_SNI=%s\n' "$BIBA_INVITE_SNI"
  printf 'BIBA_YB_MESH_ENDPOINT=%s\n' "${BIBA_YB_MESH_ENDPOINT:-}"
  printf 'BIBA_SERVER_IMAGE=%s\n' "$BIBA_SERVER_IMAGE"
  printf 'BIBA_MESH_IMAGE=%s\n' "$BIBA_MESH_IMAGE"
} >"$ENV_FILE"

echo "Values saved to $ENV_FILE (do not commit)" >&2
echo "Connect: ${BIBA_INVITE_PUBLIC} (SNI: ${BIBA_INVITE_SNI})" >&2
echo "Starting biba-server (docker compose up -d)..." >&2
if [[ "$mesh" == 0 ]]; then
  "${compose[@]}" --env-file "$ENV_FILE" --profile yb-mesh stop yb-mesh
fi
"${compose[@]}" --env-file "$ENV_FILE" up -d --no-build --pull never biba-server
if [[ "$mesh" == 1 ]]; then
  "${compose[@]}" --env-file "$ENV_FILE" --profile yb-mesh up -d --no-build --pull never yb-mesh
fi

INVITE_URI=""
i=0
while [[ $i -lt 90 ]]; do
  log="$("${compose[@]}" --env-file "$ENV_FILE" logs --no-color --tail=200 biba-server 2>&1 || true)"
  if [[ "$log" =~ (biba://[^[:space:]]+) ]]; then
    INVITE_URI="${BASH_REMATCH[1]}"
    break
  fi
  sleep 1
  i=$((i + 1))
done

if [[ -z "$INVITE_URI" ]]; then
  echo "start.sh: invite URI not found in server logs" >&2
  exit 1
fi

echo ""
echo "Invite URI — encrypted one-line config for the client (paste this as the biba:// key / invite field):"
echo "$INVITE_URI"
echo ""
echo "Passphrase — secret key that decrypts the URI; share it only out-of-band, never bundled with the URI in chat or tickets:"
echo "$BIBA_INVITE_PASSPHRASE"
echo ""
