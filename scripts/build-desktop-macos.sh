#!/usr/bin/env bash
# Build desktop app with menu bar icon (macOS). Requires Xcode Command Line Tools and rustup.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"
cargo build -p bibavpn-desktop --release
echo "Done: $REPO_ROOT/target/release/bibavpn-desktop"
