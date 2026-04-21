#!/bin/sh
export PATH="$HOME/.cargo/bin:$PATH"
cd "$(dirname "$0")/.." || exit 1
exec cargo check -p bibavpn --features boring-tls "$@"
