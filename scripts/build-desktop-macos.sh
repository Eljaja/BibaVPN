#!/usr/bin/env bash
# Сборка десктопа с иконкой в строке меню (macOS). Нужны Xcode Command Line Tools и rustup.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"
cargo build -p bibavpn-desktop --release
echo "Готово: $REPO_ROOT/target/release/bibavpn-desktop"
