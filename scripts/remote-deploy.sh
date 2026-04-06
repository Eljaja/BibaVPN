#!/usr/bin/env bash
# Deploy biba-vpn sources to server from server.txt (run from WSL). Not for CI.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TXT="$(cd "$(dirname "$0")/../.." && pwd)/server.txt"
if [[ ! -f "$TXT" ]]; then
  echo "missing $TXT" >&2
  exit 1
fi
HOST="$(sed -n '2p' "$TXT" | tr -d '\r')"
USER_="$(sed -n '4p' "$TXT" | tr -d '\r')"
PASS="$(sed -n '6p' "$TXT" | tr -d '\r')"
PORT="$(sed -n '8p' "$TXT" | tr -d '\r')"
REM_DIR="/root/biba-vpn"
SAN="$HOST"

run() {
  sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no -p "$PORT" "$USER_@$HOST" "$@"
}

echo "Build Linux binary locally"
( cd "$ROOT" && cargo build --release -p bibavpn --bin bibavpn-server )

echo "Sync $ROOT -> $USER_@$HOST:$REM_DIR"
run "rm -rf '$REM_DIR' && install -d -m 0755 '$REM_DIR'"
tar cf - --exclude=target --exclude=.git -C "$ROOT" . \
  | sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no -p "$PORT" "$USER_@$HOST" "tar xf - -C '$REM_DIR'"

echo "Upload prebuilt bibavpn-server + free Docker disk (small VPS)"
sshpass -p "$PASS" scp -o StrictHostKeyChecking=no -P "$PORT" \
  "$ROOT/target/release/bibavpn-server" "$USER_@$HOST:$REM_DIR/bibavpn-server"
run "chmod +x '$REM_DIR/bibavpn-server'"
run "docker image prune -f 2>/dev/null || true; docker builder prune -af 2>/dev/null || true"

echo "Docker build bibavpn-server:local (slim image, no Rust toolchain on server)"
run "cd '$REM_DIR' && docker build -f docker/Dockerfile.server.binary -t bibavpn-server:local ."

echo "Restart bibavpn container"
run "docker stop bibavpn 2>/dev/null || true; docker rm bibavpn 2>/dev/null || true"
run "docker run -d --name bibavpn --restart unless-stopped -p 8443:8443 bibavpn-server:local \
  --listen 0.0.0.0:8443 \
  --self-signed-san $SAN \
  --token REDACTED_TOKEN \
  --psk REDACTED_PSK \
  --decoy-max 32 \
  --max-pad 64 \
  --max-ws-binary 1400 \
  --ws-ping-secs 25"

run "docker ps --filter name=bibavpn"
echo "Done."
