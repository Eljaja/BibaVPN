#!/usr/bin/env bash
# Local BibaVPN stack + SOCKS e2e. Run from repo root: ./scripts/run_e2e.sh
# With client already up: BIBAVPN_SKIP_STACK=1 BIBAVPN_SOCKS_PORT=1080 ./scripts/run_e2e.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PROFILE=debug
if [[ "${BIBAVPN_RELEASE:-}" == "1" ]]; then PROFILE=release; fi

if [[ -n "${BIBAVPN_SERVER_EXE:-}" && -n "${BIBAVPN_CLIENT_EXE:-}" ]]; then
  echo "[e2e] using BIBAVPN_SERVER_EXE / BIBAVPN_CLIENT_EXE"
  SERVER_EXE="$BIBAVPN_SERVER_EXE"
  CLIENT_EXE="$BIBAVPN_CLIENT_EXE"
else
  echo "[e2e] cargo build -p bibavpn --bins ($PROFILE)"
  if [[ "$PROFILE" == release ]]; then
    cargo build -p bibavpn --bins --release
  else
    cargo build -p bibavpn --bins
  fi
  SERVER_EXE="$ROOT/target/$PROFILE/bibavpn-server"
  CLIENT_EXE="$ROOT/target/$PROFILE/bibavpn-client"
fi

VPN_PORT="${BIBAVPN_LOCAL_PORT:-$((38443 + RANDOM % 2000))}"
SOCKS_PORT="${BIBAVPN_SOCKS_PORT:-$((11080 + RANDOM % 2000))}"
TOKEN="${BIBAVPN_TOKEN:-e2e-local-token}"

cleanup() {
  [[ -n "${CLIENT_PID:-}" ]] && kill "$CLIENT_PID" 2>/dev/null || true
  [[ -n "${SERVER_PID:-}" ]] && kill "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT

if [[ "${BIBAVPN_SKIP_STACK:-}" != "1" ]]; then
  echo "[e2e] starting bibavpn-server on 127.0.0.1:${VPN_PORT}"
  "$SERVER_EXE" \
    --listen "127.0.0.1:${VPN_PORT}" \
    --self-signed-san localhost \
    --token "$TOKEN" \
    --ws-path /ws \
    --ws-ping-secs 10 \
 &
  SERVER_PID=$!
  sleep 1

  echo "[e2e] starting bibavpn-client SOCKS 127.0.0.1:${SOCKS_PORT}"
  "$CLIENT_EXE" \
    --server "127.0.0.1:${VPN_PORT}" \
    --sni localhost \
    --token "$TOKEN" \
    --insecure \
    --socks5 "127.0.0.1:${SOCKS_PORT}" \
    --ws-ping-secs 10 \
    &
  CLIENT_PID=$!
else
  echo "[e2e] BIBAVPN_SKIP_STACK=1 - SOCKS 127.0.0.1:${SOCKS_PORT}"
fi

for _ in $(seq 1 150); do
  if nc -z 127.0.0.1 "$SOCKS_PORT" 2>/dev/null; then break; fi
  sleep 0.2
done
if ! nc -z 127.0.0.1 "$SOCKS_PORT" 2>/dev/null; then
  echo "[e2e] SOCKS not reachable on 127.0.0.1:${SOCKS_PORT}" >&2
  exit 1
fi

E2E="$ROOT/scripts/bibavpn_e2e.py"
if command -v python3 >/dev/null 2>&1; then PY=python3
elif command -v python >/dev/null 2>&1; then PY=python
else echo "[e2e] python3 not found" >&2; exit 1
fi

"$PY" "$E2E" --socks-host 127.0.0.1 --socks-port "$SOCKS_PORT" "$@"
