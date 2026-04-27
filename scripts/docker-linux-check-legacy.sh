#!/usr/bin/env bash
# Запуск внутри контейнера с Rust (например rust:1-trixie), без отдельного Dockerfile.
# Хост:
#   docker run --rm --dns 8.8.8.8 --dns 8.8.4.4 \
#     -v "$(pwd)":/work -w /work rust:1-trixie bash scripts/docker-linux-check-legacy.sh
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y \
  build-essential pkg-config libssl-dev \
  libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev \
  libwebkit2gtk-4.1-dev cmake nasm git ca-certificates \
  clang libclang-dev
cd /work
export CARGO_TARGET_DIR=/tmp/bibavpn-target
mkdir -p "$CARGO_TARGET_DIR"
exec cargo check -p bibavpn-desktop
