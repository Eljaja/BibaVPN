#!/usr/bin/env bash
# Deploy bibavpn-client Docker image to a LAN host via SSH + sshpass.
#
# Usage:
#   export SSHPASS='...'                  # password for the LAN user
#   export BIBA_LAN_HOST=192.168.1.10
#   export BIBA_LAN_USER=youruser
#   export BIBA_REMOTE=vpn.example.com:8443
#   export BIBA_SNI=vpn.example.com
#   export BIBA_VPN_TOKEN='...'
#   export BIBA_VPN_PSK='...'
#   ./scripts/lan-install-client.sh
#
# Optional tuning (sane defaults in brackets):
#   BIBA_DECOY_MAX [32]  BIBA_MAX_PAD [64]  BIBA_MAX_WS_BINARY [1400]
#   BIBA_WS_PING_SECS [25]  BIBA_EARLY_WS_FRAMES [0]
#   BIBA_SOCKS_PORT [11090]  BIBA_HTTP_PORT [11880]
#   BIBA_CLIENT_NO_CACHE=1 — force `docker build --no-cache`.

set -euo pipefail
: "${BIBA_LAN_HOST:?set BIBA_LAN_HOST}"
: "${BIBA_LAN_USER:?set BIBA_LAN_USER}"
: "${SSHPASS:?set SSHPASS for the LAN user}"

: "${BIBA_REMOTE:?set BIBA_REMOTE=host:port (your bibavpn-server endpoint)}"
: "${BIBA_SNI:?set BIBA_SNI (TLS SNI for the server)}"
: "${BIBA_VPN_TOKEN:?set BIBA_VPN_TOKEN}"
: "${BIBA_VPN_PSK:?set BIBA_VPN_PSK}"

: "${BIBA_DECOY_MAX:=32}"
: "${BIBA_MAX_PAD:=64}"
: "${BIBA_MAX_WS_BINARY:=1400}"
: "${BIBA_WS_PING_SECS:=25}"
: "${BIBA_EARLY_WS_FRAMES:=0}"
: "${BIBA_SOCKS_PORT:=11090}"
: "${BIBA_HTTP_PORT:=11880}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SSH=(sshpass -e ssh -o StrictHostKeyChecking=accept-new "${BIBA_LAN_USER}@${BIBA_LAN_HOST}")
SCP=(sshpass -e scp -o StrictHostKeyChecking=accept-new)

if ! command -v sshpass >/dev/null; then
  echo "Install sshpass (e.g. sudo apt install sshpass)" >&2
  exit 1
fi

BUILD=(docker build -t bibavpn-client:local -f "$ROOT/docker/Dockerfile.client" "$ROOT")
if [[ "${BIBA_CLIENT_NO_CACHE:-}" == 1 ]]; then
  BUILD=(docker build --no-cache -t bibavpn-client:local -f "$ROOT/docker/Dockerfile.client" "$ROOT")
fi
"${BUILD[@]}"
docker save bibavpn-client:local | gzip > /tmp/bibavpn-client.tgz
"${SCP[@]}" /tmp/bibavpn-client.tgz "${BIBA_LAN_USER}@${BIBA_LAN_HOST}:/tmp/bibavpn-client.tgz"

"${SSH[@]}" 'command -v docker >/dev/null || { echo "docker not found on LAN host"; exit 1; }'

"${SSH[@]}" 'gunzip -c /tmp/bibavpn-client.tgz | docker load'

"${SSH[@]}" "docker rm -f bibavpn-client 2>/dev/null || true; docker run -d --name bibavpn-client --restart unless-stopped \
  -p ${BIBA_SOCKS_PORT}:${BIBA_SOCKS_PORT} \
  -p ${BIBA_HTTP_PORT}:18080 \
  bibavpn-client:local \
  --server ${BIBA_REMOTE} \
  --sni ${BIBA_SNI} \
  --token ${BIBA_VPN_TOKEN} \
  --insecure \
  --socks5 0.0.0.0:${BIBA_SOCKS_PORT} \
  --http-proxy 0.0.0.0:18080 \
  --psk ${BIBA_VPN_PSK} \
  --decoy-max ${BIBA_DECOY_MAX} \
  --max-pad ${BIBA_MAX_PAD} \
  --max-ws-binary ${BIBA_MAX_WS_BINARY} \
  --ws-ping-secs ${BIBA_WS_PING_SECS} \
  --early-ws-frames ${BIBA_EARLY_WS_FRAMES}"

echo "OK: bibavpn-client on ${BIBA_LAN_HOST}"
echo "  SOCKS5: ${BIBA_LAN_HOST}:${BIBA_SOCKS_PORT}"
echo "  HTTP CONNECT: ${BIBA_LAN_HOST}:${BIBA_HTTP_PORT}"
