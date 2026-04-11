#!/usr/bin/env bash
# Local BibaVPN + long "real app" stress (ChatGPT-like stream, Slack-like WS push, Telegram-like UDP).
# From repo root: ./scripts/run_e2e_long.sh
# Duration (seconds): BIBAVPN_LONG_SECS (default 900 = 15 min)
# Existing client: BIBAVPN_SKIP_STACK=1 BIBAVPN_SOCKS_PORT=1080 ./scripts/run_e2e_long.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PROFILE=debug
if [[ "${BIBAVPN_RELEASE:-}" == "1" ]]; then PROFILE=release; fi

DURATION="${BIBAVPN_LONG_SECS:-900}"

if [[ -n "${BIBAVPN_SERVER_EXE:-}" && -n "${BIBAVPN_CLIENT_EXE:-}" ]]; then
  echo "[long] using BIBAVPN_SERVER_EXE / BIBAVPN_CLIENT_EXE"
  SERVER_EXE="$BIBAVPN_SERVER_EXE"
  CLIENT_EXE="$BIBAVPN_CLIENT_EXE"
else
  echo "[long] cargo build -p bibavpn --bins ($PROFILE)"
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
  echo "[long] starting bibavpn-server on 127.0.0.1:${VPN_PORT}"
  "$SERVER_EXE" \
    --listen "127.0.0.1:${VPN_PORT}" \
    --self-signed-san localhost \
    --token "$TOKEN" \
    --ws-path /ws \
    --ws-ping-secs 15 \
 &
  SERVER_PID=$!
  sleep 1

  echo "[long] starting bibavpn-client SOCKS 127.0.0.1:${SOCKS_PORT}"
  "$CLIENT_EXE" \
    --server "127.0.0.1:${VPN_PORT}" \
    --sni localhost \
    --token "$TOKEN" \
    --insecure \
    --socks5 "127.0.0.1:${SOCKS_PORT}" \
    --ws-ping-secs 15 \
    &
  CLIENT_PID=$!
  echo "[long] waiting for SOCKS (3s)..."
  sleep 3
else
  echo "[long] BIBAVPN_SKIP_STACK=1 - wait for SOCKS 127.0.0.1:${SOCKS_PORT}"
  for _ in $(seq 1 150); do
    if nc -z 127.0.0.1 "$SOCKS_PORT" 2>/dev/null; then break; fi
    sleep 0.2
  done
fi

if ! nc -z 127.0.0.1 "$SOCKS_PORT" 2>/dev/null; then
  echo "[long] SOCKS not reachable on 127.0.0.1:${SOCKS_PORT}" >&2
  exit 1
fi

STRESS="$ROOT/scripts/bibavpn_realworld_stress.py"
if command -v python3 >/dev/null 2>&1; then PY=python3
elif command -v python >/dev/null 2>&1; then PY=python
else echo "[long] python3 not found" >&2; exit 1
fi

echo "[long] running stress ${DURATION}s (set BIBAVPN_LONG_SECS to change)"
export BIBAVPN_LONG_SECS="$DURATION"
"$PY" "$STRESS" --socks-host 127.0.0.1 --socks-port "$SOCKS_PORT" --duration-sec "$DURATION" "$@"
