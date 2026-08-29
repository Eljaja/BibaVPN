#!/usr/bin/env bash
# Fetch split-tunnel / bypass-domains JSON for compile-time embedding.
# Used by desktop + Android CI. Requires curl; uses python3 when available to validate.
#
# Env:
#   BIBA_BYPASS_DOMAINS_URL — control-plane URL (repo secret). If unset, writes an empty payload.
#   BIBA_BYPASS_DOMAINS_OUT — optional output path (default: apps/bibavpn-desktop/src-tauri/embedded/bypass_domains.json)
#   BIBA_BYPASS_DOMAINS_REQUIRED — if "1"/"true", fail when URL is missing or fetch fails (release builds).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${BIBA_BYPASS_DOMAINS_OUT:-$ROOT/apps/bibavpn-desktop/src-tauri/embedded/bypass_domains.json}"
REQUIRED="${BIBA_BYPASS_DOMAINS_REQUIRED:-0}"
URL="${BIBA_BYPASS_DOMAINS_URL:-}"
EMPTY_JSON='{"version":1,"ttl_sec":86400,"presets":[]}'

mkdir -p "$(dirname "$OUT")"

is_required() {
  case "$(printf '%s' "$REQUIRED" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

write_empty() {
  printf '%s\n' "$EMPTY_JSON" >"$OUT"
  echo "ci-fetch-bypass-domains: wrote empty embedded list → $OUT"
}

validate_json() {
  local path="$1"
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$path" <<'PY'
import json, sys
path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    data = json.load(f)
presets = data.get("presets")
if not isinstance(presets, list):
    raise SystemExit("bypass-domains JSON: missing presets[]")
if len(presets) == 0:
    raise SystemExit("bypass-domains JSON: presets[] is empty")
n_dom = sum(len(p.get("domains") or []) for p in presets if isinstance(p, dict))
print(f"ok: {len(presets)} presets, {n_dom} domains")
PY
  else
    # Minimal check without python
    grep -q '"presets"' "$path"
  fi
}

if [ -z "$URL" ]; then
  if is_required; then
    echo "::error::BIBA_BYPASS_DOMAINS_URL secret is required but not set" >&2
    exit 1
  fi
  write_empty
  exit 0
fi

TMP="${OUT}.tmp"
echo "ci-fetch-bypass-domains: GET $URL"
if ! curl -fsSL --max-time 90 -A "bibavpn-ci/1.0" "$URL" -o "$TMP"; then
  echo "::error::Failed to fetch BIBA_BYPASS_DOMAINS_URL" >&2
  rm -f "$TMP"
  if is_required; then
    exit 1
  fi
  write_empty
  exit 0
fi

if ! validate_json "$TMP"; then
  echo "::error::Fetched bypass-domains payload failed validation" >&2
  head -c 400 "$TMP" >&2 || true
  echo >&2
  rm -f "$TMP"
  if is_required; then
    exit 1
  fi
  write_empty
  exit 0
fi

mv "$TMP" "$OUT"
echo "ci-fetch-bypass-domains: embedded → $OUT ($(wc -c <"$OUT") bytes)"
