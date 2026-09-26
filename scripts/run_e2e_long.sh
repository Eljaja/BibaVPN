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
# A PSK is mandatory unless REALITY is fully configured (see startup_secrets::require_psk).
# This is a throwaway loopback value, not a secret: override with BIBAVPN_PSK.
PSK="${BIBAVPN_PSK:-e2e-local-psk}"

# Server and client stdout+stderr go to log files instead of this script's own
# scroll, so the "did any traffic bypass the tunnel?" check below can grep them
# instead of relying on a human eyeballing the output. BIBAVPN_E2E_LOGDIR
# overrides the location (e.g. so CI can upload it as an artifact); default is
# a fresh mktemp -d per run.
LOGDIR="${BIBAVPN_E2E_LOGDIR:-$(mktemp -d)}"
mkdir -p "$LOGDIR"
SERVER_LOG="$LOGDIR/server.log"
CLIENT_LOG="$LOGDIR/client.log"
echo "[long] server log: $SERVER_LOG"
echo "[long] client log: $CLIENT_LOG"

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
    --psk "$PSK" \
    --ws-path /ws \
    --ws-ping-secs 15 \
    >"$SERVER_LOG" 2>&1 &
  SERVER_PID=$!
  sleep 1

  echo "[long] starting bibavpn-client SOCKS 127.0.0.1:${SOCKS_PORT}"
  "$CLIENT_EXE" \
    --server "127.0.0.1:${VPN_PORT}" \
    --sni localhost \
    --token "$TOKEN" \
    --psk "$PSK" \
    --insecure \
    --socks5 "127.0.0.1:${SOCKS_PORT}" \
    --ws-ping-secs 15 \
    >"$CLIENT_LOG" 2>&1 &
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

# Run the python suite without bash's errexit so a nonzero exit doesn't kill
# this script before it gets a chance to inspect the logs below.
set +e
"$PY" "$STRESS" --socks-host 127.0.0.1 --socks-port "$SOCKS_PORT" --duration-sec "$DURATION" "$@"
PY_RC=$?
set -e

# The whole point of this suite is "traffic actually crossed the tunnel". If
# the client instead routed it direct (split-tunnel bypass), the python suite
# can still report success while having proven nothing: it never exercised the
# tunnel at all. domain_route::host_is_local_or_private() (see
# bibavpn/src/local_client.rs, log_direct_bypass) routes loopback/RFC1918
# targets and the literal hostname "localhost" direct, which is exactly what
# used to happen here before --target-host defaulted to a name that merely
# *resolves* to loopback. Only checked when this script started the client
# itself: BIBAVPN_SKIP_STACK=1 means there is no client log to check.
BYPASS_FOUND=0
BYPASS_MATCHES=""
if [[ "${BIBAVPN_SKIP_STACK:-}" != "1" && -f "$CLIENT_LOG" ]]; then
  BYPASS_MATCHES="$(grep "split tunnel: routing connection direct (bypass)" "$CLIENT_LOG" || true)"
  if [[ -n "$BYPASS_MATCHES" ]]; then
    BYPASS_FOUND=1
  fi
fi

if [[ "$PY_RC" -ne 0 || "$BYPASS_FOUND" -ne 0 ]]; then
  {
    if [[ "$BYPASS_FOUND" -ne 0 ]]; then
      echo "[long] FAIL: the client log shows split-tunnel bypass connection(s) below."
      echo "[long] That means the e2e traffic never entered the tunnel, so this run"
      echo "[long] proved nothing either way. This happens when --target-host (or"
      echo "[long] BIBAVPN_E2E_TARGET_HOST) is 'localhost', an IP literal, or otherwise"
      echo "[long] resolves to a loopback/RFC1918 address -- see"
      echo "[long] domain_route::host_is_local_or_private() in bibavpn/src/domain_route.rs."
      echo "[long] Use a hostname that only *resolves* to 127.0.0.1 (default: localtest.me)."
      echo "[long] matching client log line(s):"
      echo "$BYPASS_MATCHES"
    fi
    echo "[long] ---- server log tail ($SERVER_LOG) ----"
    tail -n 200 "$SERVER_LOG" 2>/dev/null || echo "[long] (no server log - BIBAVPN_SKIP_STACK=1?)"
    echo "[long] ---- client log tail ($CLIENT_LOG) ----"
    tail -n 200 "$CLIENT_LOG" 2>/dev/null || echo "[long] (no client log - BIBAVPN_SKIP_STACK=1?)"
  } >&2
fi

if [[ "$PY_RC" -ne 0 ]]; then
  exit "$PY_RC"
fi
if [[ "$BYPASS_FOUND" -ne 0 ]]; then
  exit 1
fi
exit 0
