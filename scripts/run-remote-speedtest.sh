#!/usr/bin/env bash
# Run speedtest on the VPS (from the server itself). Reads SSH secrets from server.txt (gitignored).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SERVERTXT="${BIBA_SERVER_TXT:-$ROOT/../server.txt}"
PASS="$(sed -n '6p' "$SERVERTXT" | tr -d '\r')"
export SSHPASS="$PASS"
HOST="$(sed -n '2p' "$SERVERTXT" | tr -d '\r')"
PORT="$(sed -n '8p' "$SERVERTXT" | tr -d '\r')"

run_remote() {
  sshpass -e ssh -p "$PORT" -o StrictHostKeyChecking=accept-new "root@$HOST" bash -s
}

run_remote << 'REMOTE'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv
python3 -m venv /tmp/biba-st-remote
/tmp/biba-st-remote/bin/pip install -q speedtest-cli
echo "=== Speedtest on VPS (direct from server) ==="
/tmp/biba-st-remote/bin/speedtest-cli --simple
REMOTE
