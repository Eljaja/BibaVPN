#!/usr/bin/env bash
# Load pre-uploaded /tmp/bibavpn-remote.tar.gz, run bibavpn container, print invite.
set -euo pipefail
: "${BIBA_VPS_IP:?BIBA_VPS_IP}"
: "${BIBA_TGZ_PATH:?BIBA_TGZ_PATH to tarball on remote e.g. /tmp/bibavpn-remote.tar.gz}"

systemctl stop bibavpn 2>/dev/null || true
pkill -f '/opt/bibavpn/bibavpn-server' 2>/dev/null || true

gunzip -c "$BIBA_TGZ_PATH" | docker load
docker rm -f bibavpn 2>/dev/null || true

TOKEN="$(openssl rand -hex 16)"
PSK="$(openssl rand -hex 32)"
PASS="$(openssl rand -hex 24)"

docker run -d --name bibavpn --restart unless-stopped -p 8443:8443 \
  bibavpn-server:remote \
  --listen 0.0.0.0:8443 \
  --self-signed-san "${BIBA_VPS_IP}" \
  --token "$TOKEN" \
  --psk "$PSK" \
  --decoy-max 32 \
  --max-pad 64 \
  --max-ws-binary 1400 \
  --ws-ping-secs 25 \
  --proto-domain default \
  --print-invite-uri \
  --invite-passphrase "$PASS" \
  --invite-public "${BIBA_VPS_IP}:8443" \
  --invite-sni "${BIBA_VPS_IP}"

for i in $(seq 1 45); do
  if log="$(docker logs --tail 80 bibavpn 2>&1)"; then
    if echo "$log" | grep -qE 'biba://'; then
      break
    fi
  fi
  sleep 1
done

INV="$(docker logs --tail 200 bibavpn 2>&1 | tr '\r' '\n' | grep -oE 'biba://[^[:space:]]+' | head -1 || true)"
echo ""
echo "=== biba-invite (one line) ==="
echo "${INV:-<not in logs yet: docker logs bibavpn>}"
echo "=== passcode (Invite passphrase) ==="
echo "$PASS"
if [[ -n "${BIBA_PRINT_SECRETS:-}" ]]; then
  echo "=== (internal) token / psk (manual client) ==="
  echo "TOKEN=$TOKEN"
  echo "PSK=$PSK"
fi
echo ""
docker ps --filter name=bibavpn
