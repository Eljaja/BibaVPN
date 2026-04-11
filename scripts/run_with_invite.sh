#!/usr/bin/env bash
# Run Internet-facing SOCKS probes + optional mixed load against bibavpn-client.
# (Local 127.0.0.1 echo tests do NOT work when the server is remote — use BIBAVPN_USE_LOCAL_ECHO=1 only for same-host stacks.)
# Usage:
#   ./scripts/run_with_invite.sh 'biba://...' 'passphrase' [socks_host:port]
# Or from files (no secrets in argv):
#   BIBA_INVITE_FILE=/path/invite.uri BIBA_PASS_FILE=/path/pass ./scripts/run_with_invite.sh
# Or client already running:
#   BIBAVPN_SKIP_CLIENT=1 BIBAVPN_SOCKS_HOST=127.0.0.1 BIBAVPN_SOCKS_PORT=1080 ./scripts/run_with_invite.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PROFILE=debug
if [[ "${BIBAVPN_RELEASE:-}" == "1" ]]; then PROFILE=release; fi
CLIENT="$ROOT/target/$PROFILE/bibavpn-client"
STRESS_SEC="${BIBAVPN_STRESS_SEC:-240}"
DRIP_SEC="${BIBAVPN_DRIP_SEC:-35}"
DRIP_BYTES="${BIBAVPN_DRIP_BYTES:-20000}"

if [[ -n "${BIBA_INVITE_FILE:-}" ]]; then
  SOCK="${1:-127.0.0.1:${BIBAVPN_SOCKS_PORT:-11781}}"
else
  SOCK="${3:-127.0.0.1:${BIBAVPN_SOCKS_PORT:-11781}}"
fi
SOCK_HOST="${SOCK%:*}"
SOCK_PORT="${SOCK##*:}"

cleanup() {
  [[ -n "${CPID:-}" ]] && kill "$CPID" 2>/dev/null || true
}
trap cleanup EXIT

if [[ "${BIBAVPN_SKIP_CLIENT:-}" != "1" ]]; then
  if [[ -n "${BIBA_INVITE_FILE:-}" ]]; then
    INV="$(tr -d '\r\n' < "$BIBA_INVITE_FILE")"
    PASS="$(tr -d '\r\n' < "${BIBA_PASS_FILE:?set BIBA_PASS_FILE}")"
  else
    INV="${1:?invite URI required (or set BIBA_INVITE_FILE)}"
    PASS="${2:?passphrase required (or set BIBA_PASS_FILE)}"
  fi
  if [[ ! -x "$CLIENT" ]] && [[ ! -f "$CLIENT" ]]; then
    echo "[invite] building bibavpn-client..."
    cargo build -p bibavpn --bins
  fi
  echo "[invite] starting client -> SOCKS $SOCK"
  RUST_LOG="${RUST_LOG:-info}" "$CLIENT" \
    --from-invite "$INV" \
    --invite-passphrase "$PASS" \
    --socks5 "$SOCK" \
    --ws-ping-secs 20 \
    > /tmp/bibavpn-invite-client.log 2>&1 &
  CPID=$!
  sleep 4
  for _ in $(seq 1 90); do
    if nc -z "$SOCK_HOST" "$SOCK_PORT" 2>/dev/null; then break; fi
    sleep 0.3
  done
  if ! nc -z "$SOCK_HOST" "$SOCK_PORT" 2>/dev/null; then
    echo "[invite] SOCKS not up; client log:" >&2
    cat /tmp/bibavpn-invite-client.log >&2 || true
    exit 1
  fi
else
  echo "[invite] BIBAVPN_SKIP_CLIENT=1 — use existing SOCKS $SOCK_HOST:$SOCK_PORT"
  if ! nc -z "$SOCK_HOST" "$SOCK_PORT" 2>/dev/null; then
    echo "[invite] SOCKS not reachable" >&2
    exit 1
  fi
fi

if command -v python3 >/dev/null 2>&1; then PY=python3
elif command -v python >/dev/null 2>&1; then PY=python
else echo "[invite] python3 not found" >&2; exit 1
fi

echo "[invite] bibavpn_public_probe.py (drip ${DRIP_SEC}s + parallel ${STRESS_SEC}s)"
"$PY" "$ROOT/scripts/bibavpn_public_probe.py" \
  --socks-host "$SOCK_HOST" \
  --socks-port "$SOCK_PORT" \
  --drip-sec "$DRIP_SEC" \
  --drip-bytes "$DRIP_BYTES" \
  --parallel-sec "$STRESS_SEC"

if [[ "${BIBAVPN_USE_LOCAL_ECHO:-}" == "1" ]]; then
  echo "[invite] BIBAVPN_USE_LOCAL_ECHO=1 — local echo suite (remote server must reach 127.0.0.1 on VPS)"
  "$PY" "$ROOT/scripts/bibavpn_e2e.py" --socks-host "$SOCK_HOST" --socks-port "$SOCK_PORT"
  "$PY" "$ROOT/scripts/bibavpn_realworld_stress.py" \
    --socks-host "$SOCK_HOST" \
    --socks-port "$SOCK_PORT" \
    --duration-sec "$STRESS_SEC"
fi

echo "[invite] ALL REMOTE TESTS PASSED"
