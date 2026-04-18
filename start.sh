#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Generate random token and PSK
TOKEN="token_$(openssl rand -hex 16)"
PSK="PSK_$(openssl rand -hex 16)"

echo "Starting BibaVPN server..."
echo "Generated Token: $TOKEN"
echo "Generated PSK: $PSK"

# Create temporary docker-compose with generated credentials
sed -e "s/__BIBA_TOKEN__/$TOKEN/g" \
    -e "s/__BIBA_PSK__/$PSK/g" \
    "$SCRIPT_DIR/docker-compose.yml" > "$SCRIPT_DIR/docker-compose.tmp.yml"

# Start the server
docker compose -f "$SCRIPT_DIR/docker-compose.tmp.yml" up -d biba-server

echo ""
echo "BibaVPN server is running on port 8443"
echo "SOCKS5 proxy: localhost:11080"
echo "HTTP proxy: localhost:11880"