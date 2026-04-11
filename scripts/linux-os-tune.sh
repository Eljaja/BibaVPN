#!/usr/bin/env bash
# Apply Linux network and fd limits tuning for BibaVPN / high-connection servers.
# Run as root: sudo bash scripts/linux-os-tune.sh
# Options: --dry-run (print only), --no-bbr (skip BBR lines).
set -euo pipefail

DRY_RUN=0
USE_BBR=1

usage() {
  echo "Usage: $0 [--dry-run] [--no-bbr]"
  echo "  Requires root. Writes:"
  echo "    /etc/sysctl.d/99-bibavpn-tune.conf"
  echo "    /etc/sysctl.d/99-bibavpn-conntrack.conf (only if conntrack is active)"
  echo "    /etc/security/limits.d/99-bibavpn-nofile.conf"
  echo "  Optionally: systemd drop-in for bibavpn-server if the unit exists."
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --no-bbr) USE_BBR=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root (sudo)." >&2
  exit 1
fi

SYSCTL_FILE=/etc/sysctl.d/99-bibavpn-tune.conf
SYSCTL_CT=/etc/sysctl.d/99-bibavpn-conntrack.conf
LIMITS_FILE=/etc/security/limits.d/99-bibavpn-nofile.conf

write_file() {
  local path="$1"
  local mode="$2"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "===== would write: $path ====="
    cat
    echo "===== end $path ====="
    return 0
  fi
  install -d -m 0755 "$(dirname "$path")"
  cat >"$path"
  chmod "$mode" "$path"
}

# --- main sysctl (no conntrack: may be absent if module not loaded) ---
{
  echo "# BibaVPN / high-connection host (scripts/linux-os-tune.sh)"
  echo "# Socket buffers"
  echo "net.core.rmem_max = 134217728"
  echo "net.core.wmem_max = 134217728"
  echo "net.core.rmem_default = 16777216"
  echo "net.core.wmem_default = 16777216"
  echo ""
  echo "net.ipv4.tcp_rmem = 4096 87380 67108864"
  echo "net.ipv4.tcp_wmem = 4096 65536 67108864"
  echo ""
  echo "net.core.netdev_max_backlog = 16384"
  echo "net.ipv4.tcp_max_syn_backlog = 8192"
  echo "net.core.somaxconn = 8192"
  echo ""
  echo "net.ipv4.tcp_fin_timeout = 30"
  echo ""
  if [[ "$USE_BBR" -eq 1 ]]; then
    echo "# BBR + fq (kernel must support tcp_bbr)"
    echo "net.core.default_qdisc = fq"
    echo "net.ipv4.tcp_congestion_control = bbr"
  fi
} | write_file "$SYSCTL_FILE" 0644

# --- conntrack only when sysctl nodes exist ---
if [[ "$DRY_RUN" -eq 1 ]] || [[ -e /proc/sys/net/netfilter/nf_conntrack_max ]]; then
  {
    echo "# nf_conntrack (only applied if module is loaded)"
    echo "net.netfilter.nf_conntrack_max = 2000000"
    echo "net.netfilter.nf_conntrack_tcp_timeout_established = 86400"
  } | write_file "$SYSCTL_CT" 0644
else
  if [[ "$DRY_RUN" -eq 0 ]] && [[ -f "$SYSCTL_CT" ]]; then
    rm -f "$SYSCTL_CT"
    echo "Removed stale $SYSCTL_CT (conntrack not active)."
  fi
fi

# --- pam limits ---
{
  echo "# BibaVPN: open files (also set LimitNOFILE on the systemd unit)"
  echo "* soft nofile 1048576"
  echo "* hard nofile 1048576"
} | write_file "$LIMITS_FILE" 0644

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "[dry-run] skipping sysctl, modprobe, systemd"
  exit 0
fi

if [[ "$USE_BBR" -eq 1 ]]; then
  modprobe tcp_bbr 2>/dev/null || true
fi

sysctl -p "$SYSCTL_FILE" || true
if [[ -e /proc/sys/net/netfilter/nf_conntrack_max ]]; then
  sysctl -p "$SYSCTL_CT" || true
fi

# --- systemd drop-in if unit is installed ---
UNIT_DIR=/etc/systemd/system/bibavpn-server.service.d
FRAG=$(systemctl show bibavpn-server.service -p FragmentPath --value 2>/dev/null || true)
if [[ -n "$FRAG" && -f "$FRAG" ]]; then
  install -d -m 0755 "$UNIT_DIR"
  cat >"$UNIT_DIR/99-bibavpn-tune.conf" <<'EOF'
[Service]
LimitNOFILE=1048576
EOF
  chmod 0644 "$UNIT_DIR/99-bibavpn-tune.conf"
  systemctl daemon-reload
  echo "Installed $UNIT_DIR/99-bibavpn-tune.conf — run: systemctl restart bibavpn-server"
else
  echo "bibavpn-server.service not found; add under [Service]: LimitNOFILE=1048576"
fi

echo ""
echo "Done. tcp_congestion_control=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo '?')"
echo "Re-login for shell ulimit; services pick up systemd limits after restart."
