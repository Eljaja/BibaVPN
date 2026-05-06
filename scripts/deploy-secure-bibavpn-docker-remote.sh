#!/usr/bin/env bash
# From WSL (or Linux): build docker image, push to VPS via ssh, run install-bibavpn-docker-secure.sh.
# Usage:
#   export DEPLOY_VPS_IP=94.176.232.23
#   export DEPLOY_PORT=19843
#   export SSH_IDENTITY=~/.ssh/id_rsa   # optional (default: RSA, then ed25519)
#   ./scripts/deploy-secure-bibavpn-docker-remote.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DEPLOY_VPS_IP="${DEPLOY_VPS_IP:?set DEPLOY_VPS_IP}"
DEPLOY_PORT="${DEPLOY_PORT:-19843}"

# Prefer RSA; override with SSH_IDENTITY=/path/to/key
if [[ -z "${SSH_IDENTITY:-}" ]]; then
  for k in "$HOME/.ssh/id_rsa" /root/.ssh/id_rsa "$HOME/.ssh/id_ed25519" /root/.ssh/id_ed25519; do
    if [[ -f "$k" ]]; then
      SSH_IDENTITY="$k"
      break
    fi
  done
fi

if [[ -z "${SSH_IDENTITY:-}" ]] || [[ ! -f "$SSH_IDENTITY" ]]; then
  echo "SSH private key not found. Tried id_rsa, then id_ed25519 under ~/.ssh and /root/.ssh." >&2
  echo "Set: export SSH_IDENTITY=~/.ssh/id_rsa" >&2
  exit 1
fi

# Long streams (pipe image): keep connection alive; fail fast on bad host key.
SSH=(ssh -o StrictHostKeyChecking=accept-new -o "ServerAliveInterval=30" -o "ServerAliveCountMax=12" \
  -i "$SSH_IDENTITY" "root@${DEPLOY_VPS_IP}")
SCP=(scp -o StrictHostKeyChecking=accept-new -o "ServerAliveInterval=30" -i "$SSH_IDENTITY")

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required" >&2
  exit 1
fi

echo "== [0/3] SSH test (fails fast if key not in authorized_keys) =="
if ! ssh -o ConnectTimeout=12 -o BatchMode=yes -o StrictHostKeyChecking=accept-new -i "$SSH_IDENTITY" \
  "root@${DEPLOY_VPS_IP}" "true" 2>/dev/null; then
  echo "SSH to root@${DEPLOY_VPS_IP} failed (Permission denied or timeout)." >&2
  echo "Add this public key to the server: cat ${SSH_IDENTITY}.pub" >&2
  echo "Or: export SSH_IDENTITY=/path/to/your/id_rsa" >&2
  exit 1
fi

export DOCKER_BUILDKIT=1
echo "== [1/3] Building image (Rust release can take 5–15 min, output follows) =="
docker build --progress=plain -f docker/Dockerfile.server -t bibavpn-server:secure "$ROOT"
echo "== [2/3] Piping image to $DEPLOY_VPS_IP: docker save | ssh docker load (no huge local .tar) =="
"${SCP[@]}" "$ROOT/scripts/install-bibavpn-docker-secure.sh" "root@${DEPLOY_VPS_IP}:/tmp/install-bibavpn-docker-secure.sh"
docker save bibavpn-server:secure | "${SSH[@]}" "docker load"

echo "== [3/3] Running install on server =="
"${SSH[@]}" "chmod +x /tmp/install-bibavpn-docker-secure.sh && \
  DEPLOY_VPS_IP=${DEPLOY_VPS_IP} DEPLOY_PORT=${DEPLOY_PORT} BIBAVPN_IMAGE=bibavpn-server:secure \
  bash /tmp/install-bibavpn-docker-secure.sh && rm -f /tmp/install-bibavpn-docker-secure.sh"

echo "Done."
