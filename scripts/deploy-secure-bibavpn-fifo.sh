#!/usr/bin/env bash
# Host-only deploy (no Docker): copy /tmp/bibavpn-server.new to /opt/bibavpn, TLS cert, systemd.
# P-256 cert for IP, v3+PSK, adaptive + aggressive, invite via FIFO.
# Set DEPLOY_VPS_IP, run once on the VPS.
set -euo pipefail
: "${DEPLOY_VPS_IP:?set DEPLOY_VPS_IP=host (IP or name)}"
# Public / bind port on the host (e.g. 19843 for a non-default listener).
: "${DEPLOY_PORT:=8443}"
DIR="/opt/bibavpn"
# Stop a legacy container-based install if it exists; ignore errors if Docker is absent.
if command -v docker >/dev/null 2>&1; then
  docker rm -f bibavpn 2>/dev/null || true
fi
systemctl stop bibavpn 2>/dev/null || true
pkill -f '/opt/bibavpn/bibavpn-server' 2>/dev/null || true
pkill -f 'bibavpn-server' 2>/dev/null || true
sleep 1
rm -rf "$DIR"
mkdir -p "$DIR" && chmod 700 "$DIR"
cd "$DIR"
cp /tmp/bibavpn-server.new "$DIR/bibavpn-server" && chmod 755 "$DIR/bibavpn-server" && rm -f /tmp/bibavpn-server.new

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

# shellcheck disable=SC2016
cat >/etc/systemd/system/bibavpn.service <<'UNIT'
[Unit]
Description=BibaVPN (WSS) server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/bibavpn
EnvironmentFile=-/opt/bibavpn/bibavpn.env
ExecStart=/opt/bibavpn/bibavpn-server --listen 0.0.0.0:__DEPLOY_PORT__ --cert /opt/bibavpn/cert.pem --key /opt/bibavpn/key.pem --token ${BIBA_VPN_TOKEN} --psk ${BIBA_VPN_PSK} --proto-domain ${BIBA_PROTO_DOMAIN} --ws-path /ws --pad-mode adaptive --ack-profile aggressive --decoy-max 32 --max-pad 64 --max-ws-binary 262144 --ws-ping-secs 25 --ws-ping-jitter-percent 8
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT
sed "s/__DEPLOY_PORT__/${DEPLOY_PORT}/g" /etc/systemd/system/bibavpn.service > /tmp/bibavpn.service && mv /tmp/bibavpn.service /etc/systemd/system/bibavpn.service

# Capture one biba:// line, then start long-lived server under systemd
FIFO="$DIR/invite.fifo"
rm -f "$FIFO" invite.biba err.invite.log
mkfifo "$FIFO"
( while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      biba://*) printf '%s\n' "$line" >"$DIR/invite.biba"; break ;;
    esac
  done <"$FIFO" ) & RID=$!
(
  set -a && . "$DIR/bibavpn.env" && set +a
  export RUST_LOG=off
  # shellcheck disable=SC2086
  exec "$DIR/bibavpn-server" \
    --listen "0.0.0.0:${DEPLOY_PORT}" \
    --cert "$DIR/cert.pem" \
    --key "$DIR/key.pem" \
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
    --invite-sni "${DEPLOY_VPS_IP}" >"$FIFO" 2>err.invite.log
) & HID=$!
wait "$RID" || true
rm -f "$FIFO"
if kill -0 "$HID" 2>/dev/null; then kill "$HID" 2>/dev/null || true; wait "$HID" 2>/dev/null || true; fi

printf '%s' "$BIBA_INVITE_PASSPHRASE" >"$DIR/invite.pass"
chmod 600 "$DIR/invite.biba" "$DIR/invite.pass" 2>/dev/null || true

systemctl daemon-reload
systemctl enable bibavpn
systemctl start bibavpn
sleep 1
systemctl is-active --quiet bibavpn
echo "OK systemctl: $(systemctl is-active bibavpn)"

echo ""
echo "=== biba-invite (one line) ==="
cat "$DIR/invite.biba"
echo ""
echo "=== passcode (Invite passphrase) ==="
cat "$DIR/invite.pass"
echo ""
