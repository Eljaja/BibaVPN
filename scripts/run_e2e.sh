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
echo "[e2e] server log: $SERVER_LOG"
echo "[e2e] client log: $CLIENT_LOG"

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
    --psk "$PSK" \
    --ws-path /ws \
    --ws-ping-secs 10 \
    >"$SERVER_LOG" 2>&1 &
  SERVER_PID=$!
  sleep 1

  echo "[e2e] starting bibavpn-client SOCKS 127.0.0.1:${SOCKS_PORT}"
  "$CLIENT_EXE" \
    --server "127.0.0.1:${VPN_PORT}" \
    --sni localhost \
    --token "$TOKEN" \
    --psk "$PSK" \
    --insecure \
    --socks5 "127.0.0.1:${SOCKS_PORT}" \
    --ws-ping-secs 10 \
    >"$CLIENT_LOG" 2>&1 &
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

# Run the python suite without bash's errexit so a nonzero exit doesn't kill
# this script before it gets a chance to inspect the logs below.
set +e
"$PY" "$E2E" --socks-host 127.0.0.1 --socks-port "$SOCKS_PORT" "$@"
PY_RC=$?
set -e

# The whole point of this suite is "traffic actually crossed the tunnel". If
# the client instead routed it direct (split-tunnel bypass), the python suite
# can still print ALL TESTS PASSED while having proven nothing: it never
# exercised the tunnel at all. domain_route::host_is_local_or_private() (see
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
      echo "[e2e] FAIL: the client log shows split-tunnel bypass connection(s) below."
      echo "[e2e] That means the e2e traffic never entered the tunnel, so this run"
      echo "[e2e] proved nothing either way. This happens when --target-host (or"
      echo "[e2e] BIBAVPN_E2E_TARGET_HOST) is 'localhost', an IP literal, or otherwise"
      echo "[e2e] resolves to a loopback/RFC1918 address -- see"
      echo "[e2e] domain_route::host_is_local_or_private() in bibavpn/src/domain_route.rs."
      echo "[e2e] Use a hostname that only *resolves* to 127.0.0.1 (default: localtest.me)."
      echo "[e2e] matching client log line(s):"
      echo "$BYPASS_MATCHES"
    fi
    echo "[e2e] ---- server log tail ($SERVER_LOG) ----"
    tail -n 200 "$SERVER_LOG" 2>/dev/null || echo "[e2e] (no server log - BIBAVPN_SKIP_STACK=1?)"
    echo "[e2e] ---- client log tail ($CLIENT_LOG) ----"
    tail -n 200 "$CLIENT_LOG" 2>/dev/null || echo "[e2e] (no client log - BIBAVPN_SKIP_STACK=1?)"
  } >&2
fi

if [[ "$PY_RC" -ne 0 ]]; then
  exit "$PY_RC"
fi
if [[ "$BYPASS_FOUND" -ne 0 ]]; then
  exit 1
fi
exit 0
