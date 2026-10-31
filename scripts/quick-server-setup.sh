#!/usr/bin/env bash
# Interactive deployment on a fresh Debian/Ubuntu VPS. Run as root.
set -euo pipefail

INSTALL_DIR=/opt/bibavpn-quick
SERVER_IMAGE=eljaja/bibavpn-server:sha-54c4357

fail() { printf 'Error: %s\n' "$*" >&2; exit 1; }

valid_domain() {
  local domain="$1" label
  local -a labels
  [[ ${#domain} -le 253 && "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] || return 1
  [[ "$domain" != *..* ]] || return 1
  IFS=. read -r -a labels <<< "$domain"
  for label in "${labels[@]}"; do
    [[ ${#label} -le 63 && "$label" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$ ]] || return 1
  done
}

write_config() {
  local token psk passphrase
  umask 077
  token="$(openssl rand -hex 32)"
  psk="$(openssl rand -hex 32)"
  passphrase="$(openssl rand -hex 24)"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$INSTALL_DIR/backend-key.pem" -out "$INSTALL_DIR/backend-cert.pem" \
    -days 3650 -subj '/CN=biba-server' -addext 'subjectAltName=DNS:biba-server' >/dev/null 2>&1
  cat > "$INSTALL_DIR/server.env" <<EOF
BIBA_VPN_TOKEN=$token
BIBA_VPN_PSK=$psk
EOF
  cat > "$INSTALL_DIR/invite.env" <<EOF
BIBA_VPN_TOKEN=$token
BIBA_VPN_PSK=$psk
BIBA_INVITE_PASSPHRASE=$passphrase
BIBA_INVITE_INSECURE=false
INVITE_PUBLIC=$DOMAIN:443
INVITE_SNI=$DOMAIN
EOF
  cat > "$INSTALL_DIR/Caddyfile" <<EOF
$DOMAIN {
    reverse_proxy https://biba-server:8443 {
        transport http {
            tls_trust_pool file /certs/backend-cert.pem
        }
    }
}
EOF
  cat > "$INSTALL_DIR/compose.yaml" <<'EOF'
services:
  biba-server:
    image: eljaja/bibavpn-server:sha-54c4357
    restart: unless-stopped
    command:
      - --listen
      - 0.0.0.0:8443
      - --cert
      - /certs/backend-cert.pem
      - --key
      - /certs/backend-key.pem
      - --token
      - ${BIBA_VPN_TOKEN}
      - --psk
      - ${BIBA_VPN_PSK}
    volumes:
      - ./backend-cert.pem:/certs/backend-cert.pem:ro
      - ./backend-key.pem:/certs/backend-key.pem:ro
  caddy:
    image: caddy:2.10
    restart: unless-stopped
    depends_on:
      - biba-server
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - ./backend-cert.pem:/certs/backend-cert.pem:ro
      - caddy_data:/data
      - caddy_config:/config
volumes:
  caddy_data:
  caddy_config:
EOF
}

main() {
  local resume=0
  [[ ${EUID} -eq 0 ]] || fail 'Run this installer as root (or use sudo bash).'
  [[ -t 0 ]] || fail 'Run interactively in a terminal; do not pipe the script into bash.'
  if [[ -e "$INSTALL_DIR" ]]; then
    [[ -f "$INSTALL_DIR/compose.yaml" && -f "$INSTALL_DIR/server.env" && -f "$INSTALL_DIR/invite.env" && -f "$INSTALL_DIR/Caddyfile" && -f "$INSTALL_DIR/backend-cert.pem" && -f "$INSTALL_DIR/backend-key.pem" ]] || fail "$INSTALL_DIR already exists but is not a complete quick setup. No files were changed."
    DOMAIN="$(sed -n 's/^INVITE_SNI=//p' "$INSTALL_DIR/invite.env")"
    valid_domain "$DOMAIN" || fail 'The existing setup contains an invalid domain.'
    resume=1
  fi
  [[ -f /etc/os-release ]] || fail 'Cannot identify the operating system.'
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == debian || "${ID:-}" == ubuntu ]] || fail 'This installer supports Debian and Ubuntu.'

  printf 'BibaVPN server setup\n\nPoint a domain to this VPS and open TCP ports 80 and 443.\n'
  if [[ "$resume" == 1 ]]; then
    printf 'Resuming existing setup for %s; credentials will be preserved.\n' "$DOMAIN"
  else
    read -r -p 'Server domain: ' DOMAIN
  fi
  valid_domain "$DOMAIN" || fail 'Enter a valid public domain, for example vpn.example.com.'
  getent ahosts "$DOMAIN" >/dev/null || fail 'The domain does not resolve. Configure DNS and try again.'

  local -a packages=()
  command -v docker >/dev/null || packages+=(docker.io)
  if ! docker compose version >/dev/null 2>&1 && ! command -v docker-compose >/dev/null; then packages+=(docker-compose); fi
  command -v openssl >/dev/null || packages+=(openssl)
  command -v curl >/dev/null || packages+=(curl ca-certificates)
  command -v ss >/dev/null || packages+=(iproute2)
  if (( ${#packages[@]} )); then
    printf 'Installing Docker and required packages...\n'
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}"
  fi
  command -v curl >/dev/null || fail 'curl is required.'
  docker info >/dev/null 2>&1 || fail 'Docker is not running. Start Docker and run the installer again.'
  if docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose)
  elif command -v docker-compose >/dev/null; then
    COMPOSE=(docker-compose)
  else
    fail 'Docker Compose is missing. Install docker-compose and try again.'
  fi
  if [[ "$resume" == 0 ]]; then
    [[ -z "$(ss -H -ltn '( sport = :80 or sport = :443 )')" ]] || fail 'TCP port 80 or 443 is already in use. Free both ports and try again.'
    mkdir -m 700 "$INSTALL_DIR" || fail 'Could not create the installation directory.'
    write_config
  fi
  printf 'Starting the VPN server and obtaining a TLS certificate...\n'
  "${COMPOSE[@]}" --project-name bibavpn-quick --env-file "$INSTALL_DIR/server.env" -f "$INSTALL_DIR/compose.yaml" up -d

  local status ready=0
  for ((i=0; i<90; i++)); do
    status="$(curl --noproxy '*' --resolve "$DOMAIN:443:127.0.0.1" -sS -o /dev/null -w '%{http_code}' --connect-timeout 2 --max-time 4 "https://$DOMAIN/" 2>/dev/null || true)"
    if [[ "$status" =~ ^[1-5][0-9][0-9]$ && "$status" != 502 && "$status" != 503 && "$status" != 504 ]]; then ready=1; break; fi
    sleep 2
  done
  if [[ "$ready" != 1 ]]; then
    printf 'The server started, but the certificate or backend is not ready. Check public DNS, firewall ports 80/443, and logs:\n  %s --project-name bibavpn-quick --env-file %s/server.env -f %s/compose.yaml logs\n' "${COMPOSE[*]}" "$INSTALL_DIR" "$INSTALL_DIR" >&2
    exit 1
  fi

  local invite passphrase
  invite="$(docker run --rm --network none --env-file "$INSTALL_DIR/invite.env" --entrypoint /usr/local/bin/bibavpn-mint-invite "$SERVER_IMAGE")"
  [[ "$invite" == biba://* ]] || fail 'Could not generate an invitation.'
  passphrase="$(sed -n 's/^BIBA_INVITE_PASSPHRASE=//p' "$INSTALL_DIR/invite.env")"
  printf '\nBibaVPN server is ready!\n\nInvitation: %s\nPassphrase: %s\n\n' "$invite" "$passphrase"
  printf 'Open BibaVPN, import the invitation and passphrase, then connect.\nKeep both secret and share them through separate private channels.\n'
  printf 'Configuration and credentials are stored in %s (root only).\n' "$INSTALL_DIR"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
