#!/bin/sh
set -eu
config=/data/yggstack.toml
if [ ! -s "$config" ]; then
  umask 077
  yggstack --genconf | sed 's|^peers = \[\]|peers = ["tls://yggno.de:18227", "tls://mskaeza.i113d.ru:12632", "tls://37.205.14.171:993?key=0009e16b9e3afe7b13c3612560410434d3dfc70c8a8a0a63e51e0470cb8124f6", "tls://ygg1.mk16.de:1338?key=0000000087ee9949eeab56bd430ee8f324cad55abf3993ed9b9be63ce693e18a"]|' > "$config.tmp"
  mv "$config.tmp" "$config"
fi
if [ "${1:-}" = init ]; then
  exec yggstack --useconffile "$config" --address
fi
target_port=${BIBA_YB_MESH_FORWARD_PORT:-8443}
case "$target_port" in
  ''|*[!0-9]*) echo "Invalid BIBA_YB_MESH_FORWARD_PORT" >&2; exit 1 ;;
esac
exec yggstack --useconffile "$config" --remote-tcp "8443:$target_port"
