#!/bin/bash
set -e

# Generate random token and PSK
BIBA_TOKEN=$(openssl rand -hex 16)
BIBA_PSK=$(openssl rand -hex 16)

echo "Generated credentials:"
echo "  Token: $BIBA_TOKEN"
echo "  PSK:   $BIBA_PSK"

# Replace placeholders in docker-compose.yml
sed -e "s/__BIBA_TOKEN__/$BIBA_TOKEN/g" \
    -e "s/__BIBA_PSK__/$BIBA_PSK/g" \
    docker-compose.yml > docker-compose.tmp.yml

echo "Starting biba-server..."
docker compose -f docker-compose.tmp.yml up biba-server "$@"