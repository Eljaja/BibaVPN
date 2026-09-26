#!/usr/bin/env bash
# Run wsl-max-stealth-bench.sh three times (from repo root).
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="${HOME}/.cargo/bin:${PATH}"
for i in 1 2 3; do
  echo "========== Run ${i} of 3 =========="
  bash scripts/wsl-max-stealth-bench.sh
  echo ""
done
