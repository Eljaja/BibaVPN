#!/usr/bin/env bash
# Build bibavpn-server locally and redeploy it to a remote VPS via SSH.
# Not for CI — this is a one-liner for a personal lab. Secrets come from env.
#
# Usage (Linux / WSL):
#   export BIBA_HOST=vpn.example.com      # or IP
#   export BIBA_SSH_PORT=22
#   export BIBA_SSH_USER=root
#   export BIBA_VPN_PSK='...'
#   export BIBA_VPN_TOKEN='...'
#   # auth: either
#   export SSHPASS='...'                  # sshpass will be used
#   # or rely on the default SSH agent / keys (do not set SSHPASS)
#
#   ./scripts/remote-deploy.sh
#
# Optional knobs:
#   BIBA_REMOTE_DIR [/root/biba-vpn]  BIBA_TLS_SAN [$BIBA_HOST]
#   BIBA_DECOY_MAX [32]  BIBA_MAX_PAD [64]  BIBA_MAX_WS_BINARY [1400]
#   BIBA_WS_PING_SECS [25]

set -euo pipefail

: "${BIBA_HOST:?set BIBA_HOST}"
: "${BIBA_SSH_PORT:?set BIBA_SSH_PORT}"
: "${BIBA_VPN_PSK:?set BIBA_VPN_PSK}"
: "${BIBA_VPN_TOKEN:?set BIBA_VPN_TOKEN}"

BIBA_SSH_USER="${BIBA_SSH_USER:-root}"
REM_DIR="${BIBA_REMOTE_DIR:-/root/biba-vpn}"
SAN="${BIBA_TLS_SAN:-$BIBA_HOST}"
DECOY_MAX="${BIBA_DECOY_MAX:-32}"
MAX_PAD="${BIBA_MAX_PAD:-64}"
MAX_WS_BINARY="${BIBA_MAX_WS_BINARY:-1400}"
WS_PING_SECS="${BIBA_WS_PING_SECS:-25}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

run() {
  if [[ -n "${SSHPASS:-}" ]]; then
    sshpass -e ssh -o StrictHostKeyChecking=accept-new -p "$BIBA_SSH_PORT" "$BIBA_SSH_USER@$BIBA_HOST" "$@"
  else
    ssh -o StrictHostKeyChecking=accept-new -p "$BIBA_SSH_PORT" "$BIBA_SSH_USER@$BIBA_HOST" "$@"
  fi
}

scp_to() {
  local src="$1" dest="$2"
  if [[ -n "${SSHPASS:-}" ]]; then
    sshpass -e scp -o StrictHostKeyChecking=accept-new -P "$BIBA_SSH_PORT" "$src" "$BIBA_SSH_USER@$BIBA_HOST:$dest"
  else
    scp -o StrictHostKeyChecking=accept-new -P "$BIBA_SSH_PORT" "$src" "$BIBA_SSH_USER@$BIBA_HOST:$dest"
  fi
}

echo "Build Linux binary locally"
( cd "$ROOT" && cargo build --release -p bibavpn --bin bibavpn-server )

echo "Sync $ROOT -> $BIBA_SSH_USER@$BIBA_HOST:$REM_DIR"
run "rm -rf '$REM_DIR' && install -d -m 0755 '$REM_DIR'"
if [[ -n "${SSHPASS:-}" ]]; then
  tar cf - --exclude=target --exclude=.git -C "$ROOT" . \
    | sshpass -e ssh -o StrictHostKeyChecking=accept-new -p "$BIBA_SSH_PORT" "$BIBA_SSH_USER@$BIBA_HOST" "tar xf - -C '$REM_DIR'"
else
  tar cf - --exclude=target --exclude=.git -C "$ROOT" . \
    | ssh -o StrictHostKeyChecking=accept-new -p "$BIBA_SSH_PORT" "$BIBA_SSH_USER@$BIBA_HOST" "tar xf - -C '$REM_DIR'"
fi

echo "Upload prebuilt bibavpn-server + free Docker disk (small VPS)"
scp_to "$ROOT/target/release/bibavpn-server" "$REM_DIR/bibavpn-server"
run "chmod +x '$REM_DIR/bibavpn-server'"
run "docker image prune -f 2>/dev/null || true; docker builder prune -af 2>/dev/null || true"

echo "Docker build bibavpn-server:local (slim image, no Rust toolchain on server)"
run "cd '$REM_DIR' && docker build -f docker/Dockerfile.server.binary -t bibavpn-server:local ."

echo "Restart bibavpn container"
run "docker stop bibavpn 2>/dev/null || true; docker rm bibavpn 2>/dev/null || true"
run "docker run -d --name bibavpn --restart unless-stopped -p 8443:8443 bibavpn-server:local \
  --listen 0.0.0.0:8443 \
  --self-signed-san $SAN \
  --token $BIBA_VPN_TOKEN \
  --psk $BIBA_VPN_PSK \
  --decoy-max $DECOY_MAX \
  --max-pad $MAX_PAD \
  --max-ws-binary $MAX_WS_BINARY \
  --ws-ping-secs $WS_PING_SECS"

run "docker ps --filter name=bibavpn"
echo "Done. Server: $BIBA_HOST:8443 (SNI $SAN)"
