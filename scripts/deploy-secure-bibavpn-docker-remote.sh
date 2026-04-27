#!/usr/bin/env bash
# From WSL (or Linux): build docker image, push to VPS via ssh, run install-bibavpn-docker-secure.sh.
# Usage:
#   export DEPLOY_VPS_IP=94.176.232.23
#   export DEPLOY_PORT=19843
#   export SSH_IDENTITY=~/.ssh/id_ed25519   # optional
#   ./scripts/deploy-secure-bibavpn-docker-remote.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DEPLOY_VPS_IP="${DEPLOY_VPS_IP:?set DEPLOY_VPS_IP}"
DEPLOY_PORT="${DEPLOY_PORT:-19843}"
SSH_IDENTITY="${SSH_IDENTITY:-$HOME/.ssh/id_ed25519}"
if [[ ! -f "$SSH_IDENTITY" ]] && [[ -f /root/.ssh/id_ed25519 ]]; then
  SSH_IDENTITY=/root/.ssh/id_ed25519
fi
SSH=(ssh -o StrictHostKeyChecking=accept-new -i "$SSH_IDENTITY" "root@${DEPLOY_VPS_IP}")
SCP=(scp -o StrictHostKeyChecking=accept-new -i "$SSH_IDENTITY")

if [[ ! -f "$SSH_IDENTITY" ]]; then
  echo "SSH key not found: $SSH_IDENTITY" >&2
  echo "Set SSH_IDENTITY (e.g. /root/.ssh/id_ed25519 in WSL)." >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required" >&2
  exit 1
fi

echo "Building $ROOT (Dockerfile.server)..."
docker build -f docker/Dockerfile.server -t bibavpn-server:secure "$ROOT"
echo "Saving image to tar..."
TMP_TAR="${TMPDIR:-/tmp}/bibavpn-server-secure-$$.tar"
docker save bibavpn-server:secure -o "$TMP_TAR"
trap 'rm -f "$TMP_TAR"' EXIT

echo "Copying image and install script to $DEPLOY_VPS_IP..."
"${SCP[@]}" "$TMP_TAR" "root@${DEPLOY_VPS_IP}:/tmp/bibavpn-server-secure.tar"
"${SCP[@]}" "$ROOT/scripts/install-bibavpn-docker-secure.sh" "root@${DEPLOY_VPS_IP}:/tmp/install-bibavpn-docker-secure.sh"

echo "Loading image and installing..."
"${SSH[@]}" "docker load -i /tmp/bibavpn-server-secure.tar && chmod +x /tmp/install-bibavpn-docker-secure.sh && \
  DEPLOY_VPS_IP=${DEPLOY_VPS_IP} DEPLOY_PORT=${DEPLOY_PORT} BIBAVPN_IMAGE=bibavpn-server:secure \
  bash /tmp/install-bibavpn-docker-secure.sh && rm -f /tmp/bibavpn-server-secure.tar /tmp/install-bibavpn-docker-secure.sh"

echo "Done."
