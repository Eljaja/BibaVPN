#!/usr/bin/env bash
# Behavioral lab: several traffic shapes through BibaVPN, PCAP per scenario, then TCP metrics.
# Run in WSL from repo root:  bash scripts/wsl-behavior-lab.sh
#
# Scenarios (outer TCP to bibavpn-server):
#   mux_short      — one mux tunnel, small HTTP fetch
#   mux_idle       — same tunnel, idle ~15s, second fetch
#   mux_bulk       — one tunnel, ~4 MiB download
#   mux_keepalive  — WS ping + dummy padding, idle ~18s
#   no_mux_churn   — --no-mux, 5 sequential fetches (TLS session churn)
#
# Needs: tcpdump, openssl, curl, python3+scapy, dd. Uses tcpdump -i any (WSL2).
# Do not pass curl --noproxy '*' here: it disables SOCKS and traffic goes direct to the HTTP port.
# Optional: BEH_ONLY=mux_idle  — run a single scenario by name (debug).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
SRV="${ROOT}/target/release/bibavpn-server"
CL="${ROOT}/target/release/bibavpn-client"
MET="${ROOT}/scripts/wsl-pcap-behavior-metrics.py"
CERT_DIR="/tmp/biba_capture_certs"
TOKEN="t"

if [[ ! -x "$SRV" || ! -x "$CL" ]]; then
  echo "build first: cargo build --release -p bibavpn" >&2
  exit 1
fi

ensure_cert() {
  local port="$1"
  local crt="${CERT_DIR}/localhost-${port}.crt"
  local key="${CERT_DIR}/localhost-${port}.key"
  mkdir -p "$CERT_DIR"
  if [[ ! -f "$crt" ]]; then
    openssl req -x509 -newkey rsa:2048 -keyout "$key" -out "$crt" -days 2 -nodes -subj "/CN=localhost"
  fi
  echo "$crt"
}

free_ports() {
  fuser -k "$1/tcp" 2>/dev/null || true
  fuser -k "$2/tcp" 2>/dev/null || true
  sleep 0.2
}

# Args: name port sock  (uses SRV_EXTRA CL_EXTRA arrays from caller; dispatch on name)
run_scenario() {
  local name="$1"
  local port="$2"
  local sock="$3"
  local pcap="/tmp/biba_beh_${name}.pcap"
  local crt
  crt="$(ensure_cert "$port")"
  local key="${crt%.crt}.key"
  local http_port=$((port + 10000))

  free_ports "$port" "$sock"
  rm -f "$pcap"

  # On WSL2 + "any" + LINUX_SLL, BPF "port …" can drop post-idle tunnel packets; capture whole iface (short lab).
  tcpdump -i any -w "$pcap" >/dev/null 2>&1 &
  local tp=$!

  cleanup() {
    kill "${hpid:-}" "${cp:-}" "${sp:-}" 2>/dev/null || true
    sleep 0.2
    kill "${tp:-}" 2>/dev/null || true
    wait 2>/dev/null || true
  }
  # Avoid EXIT: on this WSL/bash combo it can run cleanup during `sleep` and stop tcpdump early.
  trap cleanup INT TERM
  sleep 0.3

  RUST_LOG=warn "$SRV" --listen "127.0.0.1:${port}" --cert "$crt" --key "$key" --token "$TOKEN" \
    --ws-path /ws "${SRV_EXTRA[@]}" &
  sp=$!
  sleep 0.8

  RUST_LOG=warn "$CL" --server "127.0.0.1:${port}" --sni localhost --token "$TOKEN" --socks5 "127.0.0.1:${sock}" \
    --ws-path /ws --tls-profile chrome70 --pin-cert "$crt" "${CL_EXTRA[@]}" &
  cp=$!
  sleep 1

  echo ok >"/tmp/biba-beh-${name}.txt"
  python3 -m http.server "${http_port}" --directory /tmp >/tmp/biba-beh-http-${name}.log 2>&1 &
  hpid=$!
  sleep 0.5

  if [[ "$name" == mux_short ]]; then
    curl -fsS -o /dev/null --max-time 20 --socks5-hostname "127.0.0.1:${sock}" \
      "http://127.0.0.1:${http_port}/biba-beh-${name}.txt"
  elif [[ "$name" == mux_idle ]]; then
    curl -fsS -o /dev/null --max-time 20 --socks5-hostname "127.0.0.1:${sock}" \
      "http://127.0.0.1:${http_port}/biba-beh-${name}.txt"
    /bin/sleep 15
    curl -fsS -o /dev/null --max-time 20 --socks5-hostname "127.0.0.1:${sock}" \
      "http://127.0.0.1:${http_port}/biba-beh-${name}.txt"
  elif [[ "$name" == mux_bulk ]]; then
    dd if=/dev/zero of="/tmp/biba_beh_bulk.bin" bs=1M count=4 status=none 2>/dev/null
    curl -fsS -o /dev/null --max-time 120 --socks5-hostname "127.0.0.1:${sock}" \
      "http://127.0.0.1:${http_port}/biba_beh_bulk.bin"
    rm -f "/tmp/biba_beh_bulk.bin"
  elif [[ "$name" == mux_keepalive ]]; then
    curl -fsS -o /dev/null --max-time 20 --socks5-hostname "127.0.0.1:${sock}" \
      "http://127.0.0.1:${http_port}/biba-beh-${name}.txt"
    sleep 18
  elif [[ "$name" == no_mux_churn ]]; then
    for _ in $(seq 1 5); do
      curl -fsS -o /dev/null --max-time 20 --socks5-hostname "127.0.0.1:${sock}" \
        "http://127.0.0.1:${http_port}/biba-beh-${name}.txt"
    done
  else
    echo "unknown scenario name: $name" >&2
    exit 2
  fi

  sleep 0.4
  cleanup
  trap - INT TERM

  echo ""
  echo "========== ${name} =========="
  python3 "$MET" "$pcap" "$port"
  echo "pcap: $pcap"
}

declare -a SRV_EXTRA=()
declare -a CL_EXTRA=()

if [[ -n "${BEH_ONLY:-}" ]]; then
  case "${BEH_ONLY}" in
    mux_short) SRV_EXTRA=(); CL_EXTRA=(); run_scenario mux_short 18530 11530 ;;
    mux_idle) SRV_EXTRA=(); CL_EXTRA=(); run_scenario mux_idle 18531 11531 ;;
    mux_bulk) SRV_EXTRA=(); CL_EXTRA=(); run_scenario mux_bulk 18532 11532 ;;
    mux_keepalive)
      SRV_EXTRA=(--ws-ping-secs 5 --dummy-interval-secs 3)
      CL_EXTRA=(--ws-ping-secs 5 --dummy-interval-secs 3)
      run_scenario mux_keepalive 18533 11533
      ;;
    no_mux_churn) SRV_EXTRA=(); CL_EXTRA=(--no-mux); run_scenario no_mux_churn 18534 11534 ;;
    *)
      echo "unknown BEH_ONLY=${BEH_ONLY}" >&2
      exit 2
      ;;
  esac
else
  # Call scenarios at top-level (not from a function) — avoids odd bash/WSL interactions
  # observed where mux_idle's sleep was skipped when invoked from a wrapper function.
  SRV_EXTRA=()
  CL_EXTRA=()
  run_scenario mux_short 18530 11530
  sleep 1

  SRV_EXTRA=()
  CL_EXTRA=()
  run_scenario mux_idle 18531 11531
  sleep 1

  SRV_EXTRA=()
  CL_EXTRA=()
  run_scenario mux_bulk 18532 11532
  sleep 1

  SRV_EXTRA=(--ws-ping-secs 5 --dummy-interval-secs 3)
  CL_EXTRA=(--ws-ping-secs 5 --dummy-interval-secs 3)
  run_scenario mux_keepalive 18533 11533
  sleep 1

  SRV_EXTRA=()
  CL_EXTRA=(--no-mux)
  run_scenario no_mux_churn 18534 11534
fi

echo ""
echo "Done. Interpretation hints:"
echo "  mux scenarios: expect flow_count=1 (single outer TCP/TLS)."
echo "  no_mux_churn: expect several flows (one per sequential SOCKS connection)."
echo "  mux_idle: each curl closes its SOCKS TCP; mux may keep one outer WSS (no new SYN to server port on 2nd fetch). Idle may be wire-silent on outer without WS ping — wall_duration on server port can look short; check SOCKS port and mux_keepalive."
echo "  mux_bulk: large s2c, high asymmetry."
echo "  mux_keepalive: idle period with extra small packets (ping/dummy)."
