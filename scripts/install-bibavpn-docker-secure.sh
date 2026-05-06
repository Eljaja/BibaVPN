#!/usr/bin/env bash
# Run on the VPS (as root) after the image is loaded: docker load < bibavpn-server.tar
# Required: docker, openssl. Optional: ufw (will open DEPLOY_PORT/tcp).
# Env: DEPLOY_VPS_IP (default: detect), DEPLOY_PORT (default: 19843), BIBAVPN_IMAGE (default: bibavpn-server:secure)
set -euo pipefail

BIBAVPN_IMAGE="${BIBAVPN_IMAGE:-bibavpn-server:secure}"
DEPLOY_PORT="${DEPLOY_PORT:-19843}"
if [[ -z "${DEPLOY_VPS_IP:-}" ]]; then
  DEPLOY_VPS_IP="$(curl -fsS --max-time 3 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')"
fi
: "${DEPLOY_VPS_IP:?set DEPLOY_VPS_IP to this host public IP or name}"

DIR="/opt/bibavpn"
docker rm -f bibavpn bibavpn-temp 2>/dev/null || true
mkdir -p "$DIR" && chmod 700 "$DIR"
cd "$DIR"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout key.pem -out cert.pem -days 825 -nodes \
  -subj "/CN=${DEPLOY_VPS_IP}" -addext "subjectAltName=IP:${DEPLOY_VPS_IP}"

BIBA_VPN_TOKEN="$(openssl rand -hex 32)"
BIBA_VPN_PSK="$(openssl rand -hex 32)"
BIBA_INVITE_PASSPHRASE="$(openssl rand -hex 32)"
BIBA_PROTO_DOMAIN="kdf-$(openssl rand -hex 16)"

{
  echo "BIBA_VPN_TOKEN=${BIBA_VPN_TOKEN}"
  echo "BIBA_VPN_PSK=${BIBA_VPN_PSK}"
  echo "BIBA_PROTO_DOMAIN=${BIBA_PROTO_DOMAIN}"
} >bibavpn.env
chmod 600 bibavpn.env

if command -v ufw >/dev/null 2>&1; then
  ufw allow "${DEPLOY_PORT}/tcp" comment BibaVPN || true
fi

run_invite_server() {
  exec docker run -i --name bibavpn-temp \
    -e RUST_LOG=off \
    -v "$DIR:/data:ro" \
    "$BIBAVPN_IMAGE" \
    --listen "0.0.0.0:8443" \
    --cert /data/cert.pem \
    --key /data/key.pem \
    --token "$BIBA_VPN_TOKEN" \
    --psk "$BIBA_VPN_PSK" \
    --proto-domain "$BIBA_PROTO_DOMAIN" \
    --ws-path /ws \
    --pad-mode adaptive \
    --ack-profile aggressive \
    --decoy-max 32 \
    --max-pad 64 \
    --max-ws-binary 262144 \
    --ws-ping-secs 25 \
    --ws-ping-jitter-percent 8 \
    --print-invite-uri \
    --invite-passphrase "$BIBA_INVITE_PASSPHRASE" \
    --invite-public "${DEPLOY_VPS_IP}:${DEPLOY_PORT}" \
    --invite-sni "${DEPLOY_VPS_IP}"
}

run_long_server() {
  docker run --name bibavpn \
    --restart unless-stopped \
    -p "0.0.0.0:${DEPLOY_PORT}:8443" \
    -v "$DIR:/data:ro" \
    -d \
    "$BIBAVPN_IMAGE" \
    --listen "0.0.0.0:8443" \
    --cert /data/cert.pem \
    --key /data/key.pem \
    --token "$BIBA_VPN_TOKEN" \
    --psk "$BIBA_VPN_PSK" \
    --proto-domain "$BIBA_PROTO_DOMAIN" \
    --ws-path /ws \
    --pad-mode adaptive \
    --ack-profile aggressive \
    --decoy-max 32 \
    --max-pad 64 \
    --max-ws-binary 262144 \
    --ws-ping-secs 25 \
    --ws-ping-jitter-percent 8
}

FIFO="$DIR/invite.fifo"
rm -f "$FIFO" invite.biba err.invite.log
mkfifo "$FIFO"
( while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      biba://*) printf '%s\n' "$line" >"$DIR/invite.biba"; break ;;
    esac
  done <"$FIFO" ) & RID=$!
( run_invite_server >"$FIFO" 2>err.invite.log ) & HID=$!
wait "$RID" || true
rm -f "$FIFO"
if kill -0 "$HID" 2>/dev/null; then kill "$HID" 2>/dev/null || true; wait "$HID" 2>/dev/null || true; fi
docker kill bibavpn-temp 2>/dev/null || true
docker rm bibavpn-temp 2>/dev/null || true

printf '%s' "$BIBA_INVITE_PASSPHRASE" >"$DIR/invite.pass"
chmod 600 "$DIR/invite.biba" "$DIR/invite.pass" 2>/dev/null || true

run_long_server
sleep 2
docker ps --filter "name=bibavpn" --format '{{.Status}}'

if ! docker port bibavpn 2>/dev/null | grep -q .; then
  echo "ERROR: host port was not published (docker port bibavpn empty). Check docker run -p." >&2
  docker inspect bibavpn --format '{{json .NetworkSettings.Ports}}' >&2 || true
  exit 1
fi
echo "Published ports:"
docker port bibavpn

echo ""
echo "=== biba-invite (one line) ==="
cat "$DIR/invite.biba"
echo ""
echo "=== passcode (Invite passphrase) ==="
cat "$DIR/invite.pass"
echo ""
