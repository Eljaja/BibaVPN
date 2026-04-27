# syntax=docker/dockerfile:1
# Linux-сборка bibavpn-desktop (Tauri 2 + GTK/WebKit + boring-sys/bindgen).
# База: Debian trixie (актуальнее bookworm).
#
# Из каталога с Cargo.toml (этот репозиторий, папка biba-vpn):
#   ./scripts/docker-build-verify.sh
#
# DNS при сборке: у Docker Desktop `docker build --dns` часто недоступен.
# Используйте scripts/docker-build-verify.sh (buildx --network=host) или:
#   docker buildx build --network=host -f docker/Dockerfile --target verify --load .

ARG RUST_DISTRO=trixie
FROM rust:1-${RUST_DISTRO} AS base

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential pkg-config libssl-dev \
      libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev \
      libwebkit2gtk-4.1-dev cmake nasm \
      clang libclang-dev \
      git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /work
ENV CARGO_TARGET_DIR=/tmp/bibavpn-target

# Быстрая итерация: образ только с зависимостями, исходники с хоста.
#   docker buildx build --network=host -f docker/Dockerfile --target dev -t bibavpn-build:dev --load .
#   docker run --rm --dns 8.8.8.8 -v "$PWD":/work -w /work bibavpn-build:dev
FROM base AS dev
CMD ["cargo", "check", "-p", "bibavpn-desktop"]

# Полная проверка внутри образа (CI).
FROM base AS verify
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/tmp/bibavpn-target,sharing=locked \
    cargo check -p bibavpn-desktop
