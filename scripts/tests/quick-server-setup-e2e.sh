#!/usr/bin/env bash
# Isolated Docker smoke test; uses a private local CA instead of public ACME.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT/scripts/quick-server-setup.sh"
tmp="$(mktemp -d)"
project="biba-quick-test-$$"
client="$project-client"
cleanup() {
  docker rm -f "$client" >/dev/null 2>&1 || true
  docker compose -p "$project" --env-file "$tmp/server.env" -f "$tmp/compose.yaml" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT
INSTALL_DIR="$tmp"
DOMAIN=vpn.example.test
write_config
read -r http_port tls_port socks_port < <(python3 - <<'PY'
import socket
sockets = [socket.socket() for _ in range(3)]
for sock in sockets:
    sock.bind(('127.0.0.1', 0))
print(*(sock.getsockname()[1] for sock in sockets))
PY
)
sed -i "s/\"80:80\"/\"127.0.0.1:$http_port:80\"/; s/\"443:443\"/\"127.0.0.1:$tls_port:443\"/" "$tmp/compose.yaml"
sed -i "1a\\    tls internal" "$tmp/Caddyfile"
sed -i "s/INVITE_PUBLIC=.*/INVITE_PUBLIC=$DOMAIN:$tls_port/" "$tmp/invite.env"
docker compose -p "$project" --env-file "$tmp/server.env" -f "$tmp/compose.yaml" up -d >/dev/null
for ((i=0; i<60; i++)); do
  if docker compose -p "$project" --env-file "$tmp/server.env" -f "$tmp/compose.yaml" exec -T caddy cat /data/caddy/pki/authorities/local/root.crt > "$tmp/ca.crt" 2>/dev/null && \
    curl --noproxy '*' --resolve "$DOMAIN:$tls_port:127.0.0.1" --cacert "$tmp/ca.crt" -sS -o /dev/null --max-time 2 "https://$DOMAIN:$tls_port/" 2>/dev/null; then break; fi
  sleep 1
done
curl --noproxy '*' --resolve "$DOMAIN:$tls_port:127.0.0.1" --cacert "$tmp/ca.crt" -sS -o /dev/null --max-time 5 "https://$DOMAIN:$tls_port/"
openssl s_client -connect "127.0.0.1:$tls_port" -servername "$DOMAIN" </dev/null 2>/dev/null | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' > "$tmp/leaf.crt"
invite="$(docker run --rm --network none --env-file "$tmp/invite.env" --entrypoint /usr/local/bin/bibavpn-mint-invite "$SERVER_IMAGE")"
passphrase="$(sed -n 's/^BIBA_INVITE_PASSPHRASE=//p' "$tmp/invite.env")"
run_client() {
  docker run -d --name "$client" --network host --add-host "$DOMAIN:127.0.0.1" \
    -v "$tmp/leaf.crt:/leaf.crt:ro" eljaja/bibavpn-client:latest \
    --from-invite "$invite" --invite-passphrase "$passphrase" \
    --socks5 "127.0.0.1:$socks_port" "$@" >/dev/null
  for ((i=0; i<30; i++)); do
    if (echo > "/dev/tcp/127.0.0.1/$socks_port") 2>/dev/null; then return; fi
    sleep 1
  done
  printf 'Client did not start\n' >&2
  return 1
}
run_client --no-mux
if curl --noproxy '' --socks5-hostname "127.0.0.1:$socks_port" -fsS --max-time 8 -o /dev/null https://example.com/ 2>/dev/null; then
  printf 'Client accepted an untrusted TLS certificate\n' >&2
  exit 1
fi
docker rm -f "$client" >/dev/null
run_client --no-mux --pin-cert /leaf.crt
curl --noproxy '' --socks5-hostname "127.0.0.1:$socks_port" -fsS --max-time 20 -o /dev/null https://example.com/
docker rm -f "$client" >/dev/null
run_client --pin-cert /leaf.crt
curl --noproxy '' --socks5-hostname "127.0.0.1:$socks_port" -fsS --max-time 20 -o /dev/null https://example.com/
printf 'Trusted TLS, invitation and HTTPS through Caddy + BibaVPN passed\n'
