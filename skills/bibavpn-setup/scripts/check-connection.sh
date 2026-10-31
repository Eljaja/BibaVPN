#!/usr/bin/env bash
# Send one HTTP(S) request through a SOCKS5 proxy; never print the response body.
set -u

usage() {
  printf '%s\n' 'Usage: check-connection.sh --url URL [--socks HOST:PORT]' \
    'Checks HTTP(S) connectivity through a SOCKS5 proxy with remote DNS.' \
    'Default SOCKS endpoint: 127.0.0.1:1080. Exit codes: 0 success, 1 request failed, 2 invalid arguments.'
}

proxy='127.0.0.1:1080'
url=''
while (($#)); do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --socks|--url)
      if (($# < 2)) || [[ "$2" == --* ]]; then usage >&2; exit 2; fi
      if [[ "$1" == --socks ]]; then proxy=$2; else url=$2; fi
      shift 2 ;;
    *) usage >&2; exit 2 ;;
  esac
done

if [[ ! "$proxy" =~ ^(\[[0-9a-fA-F:.%]+\]|[a-zA-Z0-9._-]+):([0-9]{1,5})$ ]] || ((10#${BASH_REMATCH[2]:-0} < 1 || 10#${BASH_REMATCH[2]:-0} > 65535)); then
  printf '%s\n' 'Invalid SOCKS endpoint; expected HOST:PORT without credentials.' >&2
  exit 2
fi
if [[ ! "$url" =~ ^https?:// ]] || [[ "$url" =~ [[:space:]] ]]; then
  printf '%s\n' 'Supply an HTTP(S) target using --url.' >&2
  exit 2
fi
authority=${url#*://}
authority=${authority%%[/?#]*}
if [[ -z "$authority" || "$authority" == *@* ]]; then
  printf '%s\n' 'Target URL must have a host and must not contain credentials.' >&2
  exit 2
fi
if ! command -v curl >/dev/null 2>&1; then
  printf '%s\n' 'curl is required.' >&2
  exit 1
fi

# -q ignores curlrc; --noproxy overrides environment exclusions so this never
# silently checks a direct route. DNS for the target is requested via SOCKS.
if code=$(curl -q --silent --fail --socks5-hostname "$proxy" --noproxy '' \
    --connect-timeout 5 --max-time 15 --output /dev/null --write-out '%{http_code}' \
    -- "$url" 2>/dev/null); then
  printf 'OK: target reached through SOCKS5 (HTTP %s).\n' "$code"
else
  rc=$?
  printf 'Connection check failed (curl exit %s). See troubleshooting.md.\n' "$rc" >&2
  exit 1
fi
