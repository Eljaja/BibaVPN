#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
test_dir="$(mktemp -d)"
trap 'rm -rf "$test_dir"' EXIT
mkdir -p "$test_dir/bin"
cp "$root/start.sh" "$test_dir/start.sh"
cat >"$test_dir/bin/docker" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$DOCKER_CALLS"
case " $* " in
  *' pull '*) [[ "${FAIL_PULL:-0}" != 1 ]] ;;
  *' run '*) printf '%s\n' "${TEST_MESH_ADDRESS:-200:abcd::1}" ;;
  *' logs '*) echo 'biba://test-invite' ;;
esac
EOF
chmod +x "$test_dir/bin/docker"
export PATH="$test_dir/bin:$PATH" DOCKER_CALLS="$test_dir/calls"
cd "$test_dir"

bash start.sh > output 2>&1
grep -q 'pull biba-server' "$DOCKER_CALLS"
grep -q 'up -d --no-build --pull never biba-server' "$DOCKER_CALLS"
grep -q 'stop yb-mesh' "$DOCKER_CALLS"
grep -q '^BIBA_SERVER_IMAGE=eljaja/bibavpn-server:latest$' .biba-start.env
grep -q '^BIBA_INVITE_PUBLIC=127.0.0.1:8443$' .biba-start.env
grep -q '^BIBA_INVITE_SNI=biba-server$' .biba-start.env
! grep -q 'pull yb-mesh-init' "$DOCKER_CALLS"

: > "$DOCKER_CALLS"
bash start.sh --mesh > output 2>&1
grep -q 'pull yb-mesh-init' "$DOCKER_CALLS"
grep -q 'run --pull never --rm -T --quiet yb-mesh-init init' "$DOCKER_CALLS"
grep -q 'up -d --no-build --pull never yb-mesh' "$DOCKER_CALLS"
grep -q '^BIBA_YB_MESH_ENDPOINT=\[200:abcd::1\]:8443$' .biba-start.env
grep -q '^BIBA_SERVER_IMAGE=eljaja/bibavpn-server:mesh$' .biba-start.env
# Mesh mode must not leave 127.0.0.1 in the imported profile; the generated
# name is used as SNI, certificate SAN and the invite's display address.
mesh_name="$(sed -n 's/^BIBA_INVITE_SNI=biba-\([0-9a-f]\{8\}\)$/\1/p' .biba-start.env)"
[[ -n "$mesh_name" ]]
grep -q "^BIBA_INVITE_PUBLIC=biba-${mesh_name}:8443$" .biba-start.env
! grep -q '^BIBA_INVITE_PUBLIC=127.0.0.1' .biba-start.env
! grep -q ' compose .* build ' "$DOCKER_CALLS"

cp .biba-start.env saved-env
if FAIL_PULL=1 bash start.sh --mesh > output 2>&1; then exit 1; fi
cmp -s saved-env .biba-start.env
if TEST_MESH_ADDRESS=invalid bash start.sh --mesh > output 2>&1; then exit 1; fi
cmp -s saved-env .biba-start.env
if bash start.sh --build > output 2>&1; then exit 1; fi
echo 'start.sh prebuilt image checks passed'
