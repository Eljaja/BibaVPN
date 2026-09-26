#!/usr/bin/env bash
# On VPS: print token/psk/invite from running bibavpn container (run via ssh).
set -euo pipefail
readarray -t args < <(docker inspect bibavpn | python3 -c 'import json,sys; a=json.load(sys.stdin)[0]["Config"]["Cmd"]; [print(x) for x in a]')
i=0
while (( i < ${#args[@]} )); do
  a="${args[$i]}"
  b="${args[$i+1]:-}"
  case "$a" in
    --token) echo "TOKEN=$b" ;;
    --psk) echo "PSK=$b" ;;
    --invite-passphrase) echo "INVITE_PASSPHRASE=$b" ;;
    --invite-public) echo "INVITE_PUBLIC=$b" ;;
    --invite-sni) echo "INVITE_SNI=$b" ;;
  esac
  i=$((i+2))
done
echo ""
echo "=== biba:// (one line, from recent logs) ==="
docker logs --tail 2000 bibavpn 2>&1 | tr '\r' '\n' | grep -m1 -oE 'biba://[^[:space:]]+' | head -1
