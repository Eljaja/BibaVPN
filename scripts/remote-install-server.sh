#!/usr/bin/env bash
# Usage (do NOT commit passwords): 
#   export BIBA_SSH_PASS='...'
#   export BIBA_HOST=vpn.example.com
#   export BIBA_SSH_PORT=3333
#   ./scripts/remote-install-server.sh
#
# Installs Docker if needed and runs bibavpn-server on port 8443 with PSK from BIBA_VPN_PSK.

set -euo pipefail
: "${BIBA_HOST:?set BIBA_HOST}"
: "${BIBA_SSH_PORT:?set BIBA_SSH_PORT}"
: "${BIBA_VPN_PSK:=ChangeThisPSK}"
: "${BIBA_VPN_TOKEN:=biba-remote-token}"

SSH=(sshpass -e ssh -p "$BIBA_SSH_PORT" -o StrictHostKeyChecking=accept-new "root@$BIBA_HOST")
SCP=(sshpass -e scp -P "$BIBA_SSH_PORT" -o StrictHostKeyChecking=accept-new)

if ! command -v sshpass >/dev/null; then
  echo "Install sshpass: sudo apt install sshpass" >&2
  exit 1
fi
: "${SSHPASS:?export SSHPASS to the SSH password (sshpass), or configure SSH keys}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [[ ! -f "$ROOT/target/release/bibavpn-server" ]]; then
  (cd "$ROOT" && cargo build --release -p bibavpn --bin bibavpn-server)
fi

"${SSH[@]}" 'command -v docker >/dev/null || (apt-get update && apt-get install -y docker.io)'

docker build -t bibavpn-server:local -f "$ROOT/docker/Dockerfile.server" "$ROOT"
docker save bibavpn-server:local | gzip > /tmp/bibavpn-server.tgz
"${SCP[@]}" /tmp/bibavpn-server.tgz "root@$BIBA_HOST:/tmp/bibavpn-server.tgz"

"${SSH[@]}" 'gunzip -c /tmp/bibavpn-server.tgz | docker load'

"${SSH[@]}" "docker rm -f bibavpn 2>/dev/null || true; docker run -d --name bibavpn --restart unless-stopped -p 8443:8443 \
  bibavpn-server:local \
  --listen 0.0.0.0:8443 \
  --self-signed-san ${BIBA_HOST} \
  --token ${BIBA_VPN_TOKEN} \
  --psk ${BIBA_VPN_PSK} \
  --decoy-max 32 \
  --max-pad 64 \
  --max-ws-binary 1400 \
  --ws-ping-secs 25"

echo "Server started. Test from your PC:"
echo "  export BIBA_VPN_PSK='(same as above)'"
echo "  ./target/release/bibavpn-client --server $BIBA_HOST:8443 --sni $BIBA_HOST --token $BIBA_VPN_TOKEN --insecure --socks5 127.0.0.1:1080 --psk \"\$BIBA_VPN_PSK\" --decoy-max 32 --max-ws-binary 1400 --ws-ping-secs 25"
