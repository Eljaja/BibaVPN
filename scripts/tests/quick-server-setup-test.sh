#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=../quick-server-setup.sh
source "$ROOT/scripts/quick-server-setup.sh"

valid_domain vpn.example.com
for invalid in localhost 127.0.0.1 '-bad.example.com' 'bad..example.com' 'bad.example.com { exit }'; do
  if valid_domain "$invalid"; then
    printf 'Invalid domain accepted: %s\n' "$invalid" >&2
    exit 1
  fi
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
INSTALL_DIR="$tmp/config"
DOMAIN=vpn.example.com
mkdir -m 700 "$INSTALL_DIR"
write_config
test "$(stat -c %a "$INSTALL_DIR/server.env")" = 600
test "$(stat -c %a "$INSTALL_DIR/invite.env")" = 600
test "$(stat -c %a "$INSTALL_DIR/backend-key.pem")" = 600
grep -q '^BIBA_INVITE_INSECURE=false$' "$INSTALL_DIR/invite.env"
grep -q 'tls_trust_pool file /certs/backend-cert.pem' "$INSTALL_DIR/Caddyfile"
! grep -q 'tls_insecure_skip_verify' "$INSTALL_DIR/Caddyfile"
docker compose --env-file "$INSTALL_DIR/server.env" -f "$INSTALL_DIR/compose.yaml" config --quiet
printf 'Quick server setup configuration checks passed\n'
