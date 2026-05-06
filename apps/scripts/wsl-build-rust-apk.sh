#!/usr/bin/env bash
# Compatibility wrapper: Android is now the Tauri app, not the old standalone Gradle project.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$REPO_ROOT"
bash apps/scripts/build-android-apk-wsl.sh
