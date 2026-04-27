#!/usr/bin/env bash
# Быстрый cargo check в контейнере (без полного COPY контекста в образ).
#
# Вариант A — уже собранный слой base/dev (рекомендуется после docker-build-verify.sh
#   или один раз):
#   docker build --dns 8.8.8.8 --dns 8.8.4.4 -f docker/Dockerfile --target dev -t bibavpn-build:dev .
#   docker run --rm --dns 8.8.8.8 --dns 8.8.4.4 -v "$(pwd)":/work -w /work bibavpn-build:dev
#
# Вариант B — как раньше, один образ rust + apt (долгий первый запуск):
#   docker run --rm --dns 8.8.8.8 --dns 8.8.4.4 -v "$(pwd)":/work -w /work rust:1-trixie bash scripts/docker-linux-check-legacy.sh
#
# Полная проверка как в CI:
#   ./scripts/docker-build-verify.sh

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMG="${BIBAVPN_DEV_IMAGE:-bibavpn-build:dev}"
if ! docker image inspect "$IMG" &>/dev/null; then
  echo "Образ $IMG не найден. Соберите:" >&2
  echo "  docker buildx build --network=host -f docker/Dockerfile --target dev -t $IMG --load ." >&2
  exit 1
fi

exec docker run --rm \
  --dns 8.8.8.8 --dns 8.8.4.4 --dns 1.1.1.1 \
  -v "$ROOT:/work" -w /work \
  -e CARGO_TARGET_DIR=/tmp/bibavpn-target \
  "$IMG" \
  cargo check -p bibavpn-desktop
