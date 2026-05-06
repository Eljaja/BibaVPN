#!/usr/bin/env bash
# One-off: print biba:// line for /opt/bibavpn (same secrets; RUST_LOG=off).
# Args: public_ip host_port  e.g.  94.176.232.23 19843
set -euo pipefail
: "${1:?usage: $0 <DEPLOY_VPS_IP> <DEPLOY_PORT>}"
: "${2:?usage: $0 <DEPLOY_VPS_IP> <DEPLOY_PORT>}"
DEPLOY_VPS_IP="$1"
DEPLOY_PORT="$2"
SSH_IDENTITY="${SSH_IDENTITY:-$HOME/.ssh/id_ed25519}"
ssh -o StrictHostKeyChecking=accept-new -i "$SSH_IDENTITY" "root@${DEPLOY_VPS_IP}" \
  "DEPLOY_VPS_IP='${DEPLOY_VPS_IP}' DEPLOY_PORT='${DEPLOY_PORT}' bash -s" <<'REMOTE'
set -euo pipefail
set -a
. /opt/bibavpn/bibavpn.env
set +a
PP=$(cat /opt/bibavpn/invite.pass)
# Capture full output under a single timeout so the process always ends (pipeline with grep could leave docker running and hang SSH).
OUT=$(timeout 20 docker run --rm -e RUST_LOG=off -v /opt/bibavpn:/data:ro bibavpn-server:secure \
  --listen 127.0.0.1:54321 \
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
  --invite-passphrase "$PP" \
  --invite-public "${DEPLOY_VPS_IP}:${DEPLOY_PORT}" \
  --invite-sni "${DEPLOY_VPS_IP}" 2>&1) || true
LINE=$(printf '%s\n' "$OUT" | grep -m1 '^biba://' || true)
if [[ -z "${LINE:-}" ]]; then
  echo "fetch-biba-invite-remote: no biba:// line in output" >&2
  printf '%s\n' "$OUT" | head -30 >&2
  exit 1
fi
printf '%s\n' "$LINE"
REMOTE
