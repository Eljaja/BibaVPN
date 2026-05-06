#!/usr/bin/env bash
# Одноразово добавить source wsl-android-env.sh в ~/.bashrc
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_SH="$ROOT/apps/scripts/wsl-android-env.sh"
LINE="source \"$ENV_SH\""
if [ -f "$HOME/.bashrc" ] && grep -qF "$ENV_SH" "$HOME/.bashrc" 2>/dev/null; then
  echo "Уже есть в ~/.bashrc"
  exit 0
fi
{
  echo ""
  echo "# biba-vpn Android / Tauri (авто-добавлено $(date -I))"
  echo "$LINE"
} >> "$HOME/.bashrc"
echo "Добавлено в ~/.bashrc: $LINE"
