#!/usr/bin/env bash
# Собрать образ с целью verify (cargo check -p bibavpn-desktop) на Debian trixie.
# Запуск из каталога biba-vpn (рядом с Cargo.toml):
#   bash scripts/docker-build-verify.sh
#
# DNS: Docker Desktop / buildx часто не поддерживает `docker build --dns`.
# По умолчанию используется --network=host у buildx (на Linux/WSL2 обычно чинит резолв).
# Переопределение: BIBAVPN_DOCKER_BUILD_NETWORK=default
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="${BIBAVPN_DOCKER_IMAGE:-bibavpn-desktop:linux-check}"
NET="${BIBAVPN_DOCKER_BUILD_NETWORK:-host}"

export DOCKER_BUILDKIT=1
if [ "$NET" = "host" ]; then
  exec docker buildx build --network=host --load -f docker/Dockerfile --target verify -t "$IMAGE" .
else
  exec docker buildx build --load -f docker/Dockerfile --target verify -t "$IMAGE" .
fi
