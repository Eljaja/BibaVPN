#!/usr/bin/env bash
# Deploy biba-server in Docker on a second host port without stopping the existing container.
# Target: $BIBA_DEPLOY_HOST (required), host port $BIBA_HOST_PORT -> container 8443.
#
# Usage (from repo: biba-vpn/):
#   export BIBA_VPN_PSK='...'
#   export BIBA_VPN_TOKEN='...'
#   # optional: export BIBA_SSH_PASS='...' if not using SSH keys
#   # optional: BIBA_SSH_PORT=3333 BIBA_DEPLOY_HOST=1.2.3.4
#   # optional: BIBA_HOST_PORT=8445 BIBA_CONTAINER_NAME=bibavpn-lab ./scripts/deploy-biba-docker-alt-port.sh
#   # optional invite URI on stdout after bind (see bibavpn-server --print-invite-uri):
#   #   export BIBA_INVITE_PASSPHRASE='...'
#   #   # optional: BIBA_INVITE_SNI=example.com
#   ./scripts/deploy-biba-docker-alt-port.sh
#
# Requires: bash, ssh, scp, tar, cargo, docker on remote. sshpass only if BIBA_SSH_PASS is set.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

: "${BIBA_VPN_PSK:?set BIBA_VPN_PSK}"
: "${BIBA_VPN_TOKEN:?set BIBA_VPN_TOKEN}"

HOST="${BIBA_DEPLOY_HOST:?set BIBA_DEPLOY_HOST=host_or_ip}"
USER_="${BIBA_DEPLOY_USER:-root}"
SSH_PORT="${BIBA_SSH_PORT:-22}"
HOST_PORT="${BIBA_HOST_PORT:-8444}"
CONTAINER="${BIBA_CONTAINER_NAME:-bibavpn-p${HOST_PORT}}"
REM_DIR="${BIBA_REMOTE_DIR:-/root/biba-vpn}"
SAN="${BIBA_TLS_SAN:-$HOST}"
PUBLIC_ADDR="${HOST}:${HOST_PORT}"

INVITE_FLAGS=()
if [[ -n "${BIBA_INVITE_PASSPHRASE:-}" ]]; then
  INVITE_FLAGS+=(--print-invite-uri)
  INVITE_FLAGS+=(--invite-passphrase "$BIBA_INVITE_PASSPHRASE")
  INVITE_FLAGS+=(--invite-public "$PUBLIC_ADDR")
  if [[ -n "${BIBA_INVITE_SNI:-}" ]]; then
    INVITE_FLAGS+=(--invite-sni "$BIBA_INVITE_SNI")
  fi
fi

quote_for_remote() {
  printf '%q' "$1"
}

run() {
  if [[ -n "${BIBA_SSH_PASS:-}" ]]; then
    sshpass -p "$BIBA_SSH_PASS" ssh -p "$SSH_PORT" -o StrictHostKeyChecking=accept-new "$USER_@$HOST" "$@"
  else
    ssh -p "$SSH_PORT" -o StrictHostKeyChecking=accept-new "$USER_@$HOST" "$@"
  fi
}

scp_to() {
  local src="$1" dest="$2"
  if [[ -n "${BIBA_SSH_PASS:-}" ]]; then
    sshpass -p "$BIBA_SSH_PASS" scp -P "$SSH_PORT" -o StrictHostKeyChecking=accept-new "$src" "$USER_@$HOST:$dest"
  else
    scp -P "$SSH_PORT" -o StrictHostKeyChecking=accept-new "$src" "$USER_@$HOST:$dest"
  fi
}

if [[ -n "${BIBA_SSH_PASS:-}" ]] && ! command -v sshpass >/dev/null; then
  echo "BIBA_SSH_PASS is set but sshpass is not installed." >&2
  exit 1
fi

CAMO_LOCAL="$ROOT/camouflage-site"
if [[ ! -d "$CAMO_LOCAL" ]] || [[ ! -f "$CAMO_LOCAL/index.html" ]]; then
  echo "missing $CAMO_LOCAL (need index.html for --camouflage-dir)" >&2
  exit 1
fi

echo "Building Linux release binary locally..."
cargo build --release -p bibavpn --bin bibavpn-server

echo "Sync sources -> $USER_@$HOST:$REM_DIR (excluding target, .git, Android build caches)"
run "install -d -m 0755 '$REM_DIR'"
TAR_EXCL=(
  --exclude=target
  --exclude=.git
  --exclude=apps/android/.gradle
  --exclude=apps/android/app/build
  --exclude=apps/android/build
)
if [[ -n "${BIBA_SSH_PASS:-}" ]]; then
  tar cf - "${TAR_EXCL[@]}" -C "$ROOT" . \
    | sshpass -p "$BIBA_SSH_PASS" ssh -p "$SSH_PORT" -o StrictHostKeyChecking=accept-new "$USER_@$HOST" "tar xf - -C '$REM_DIR'"
else
  tar cf - "${TAR_EXCL[@]}" -C "$ROOT" . \
    | ssh -p "$SSH_PORT" -o StrictHostKeyChecking=accept-new "$USER_@$HOST" "tar xf - -C '$REM_DIR'"
fi

echo "Upload bibavpn-server binary"
scp_to "$ROOT/target/release/bibavpn-server" "$REM_DIR/bibavpn-server"
run "chmod +x '$REM_DIR/bibavpn-server'"

echo "Prune Docker build cache on server (optional cleanup)"
run "docker builder prune -f 2>/dev/null || true"

echo "Build image bibavpn-server:local on server (slim, Dockerfile.server.binary)"
run "cd '$REM_DIR' && docker build -f docker/Dockerfile.server.binary -t bibavpn-server:local ."

echo "Start NEW container '$CONTAINER' on host port $HOST_PORT (existing containers are not stopped)"
run "docker rm -f '$CONTAINER' 2>/dev/null || true"

REMOTE_INVITE=""
for a in "${INVITE_FLAGS[@]}"; do
  REMOTE_INVITE+=" $(quote_for_remote "$a")"
done

CAMO_HOST="${BIBA_CAMOUFLAGE_HOST_DIR:-$REM_DIR/camouflage-site}"
run "docker run -d --name '$CONTAINER' --restart unless-stopped -p ${HOST_PORT}:8443 \
  -v $(quote_for_remote "$CAMO_HOST"):/camo:ro \
  bibavpn-server:local \
  --listen 0.0.0.0:8443 \
  --self-signed-san $(quote_for_remote "$SAN") \
  --token $(quote_for_remote "$BIBA_VPN_TOKEN") \
  --psk $(quote_for_remote "$BIBA_VPN_PSK") \
  --decoy-max 32 \
  --max-pad 64 \
  --max-ws-binary 262144 \
  --ws-ping-secs 25 \
  --camouflage-dir /camo${REMOTE_INVITE}"

run "docker ps --filter name=$CONTAINER"
echo "Done. Connect clients to ${PUBLIC_ADDR} (SNI: ${SAN})."

if [[ -n "${BIBA_INVITE_PASSPHRASE:-}" ]]; then
  sleep 1
  echo "--- biba:// invite (from container stdout) ---"
  run "docker logs '$CONTAINER' 2>&1" | grep '^biba://' | head -n1 || {
    echo "(no biba:// line in logs yet; try: ssh $USER_@$HOST 'docker logs $CONTAINER')" >&2
  }
fi
