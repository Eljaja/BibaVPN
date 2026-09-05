#!/usr/bin/env bash
# Build first: cargo build --release -p bibavpn
# Compare saved builds with --client PATH --server PATH; see --help for options.
set -euo pipefail
exec python3 "$(dirname "$0")/local-throughput-bench.py" "$@"
