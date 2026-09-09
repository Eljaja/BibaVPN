#!/usr/bin/env bash
# Run trusted validation commands selected from the actual working-tree diff.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
core=false desktop=false mobile=false
while IFS= read -r -d '' path; do
  case "$path" in
    *.md) continue ;;
    Cargo.toml|Cargo.lock|rust-toolchain.toml|.github/workflows/test.yml) core=true; desktop=true; mobile=true ;;
    bibavpn/*|biba/*) core=true ;;
    apps/bibavpn-desktop/*) desktop=true ;;
    apps/bibavpn-jni/*|apps/bibavpn-ffi/*) mobile=true ;;
  esac
done < <(git diff --name-only -z HEAD; git ls-files --others --exclude-standard -z)
if [[ "${1:-}" == --plan ]]; then
  printf 'core=%s desktop=%s mobile=%s\n' "$core" "$desktop" "$mobile"
  exit 0
fi
work=.github/agent/work
mkdir -p "$work"
# The implementer's notes remain separate; this log contains runner-owned evidence.
: > "$work/TEST.log"
result=0
run_check() {
  local name="$1"; shift
  printf '\n$ %s\n' "$*" >> "$work/TEST.log"
  if "$@" > "$work/TEST-${name}.log" 2>&1; then
    cat "$work/TEST-${name}.log" >> "$work/TEST.log"
  else
    result=1
    cat "$work/TEST-${name}.log" >> "$work/TEST.log"
    printf '\nFAILED: %s\n' "$name" >> "$work/TEST.log"
  fi
}
if [[ "$desktop" == true ]]; then
  # Agent jobs run on Ubuntu; Tauri needs native GTK/WebKit build dependencies.
  run_check desktop-deps sudo apt-get update
  run_check desktop-deps-install sudo apt-get install -y libgtk-3-dev libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev patchelf
  run_check ui-install npm ci --prefix apps/bibavpn-desktop/ui --no-audit --no-fund
  run_check ui-build npm run build --prefix apps/bibavpn-desktop/ui
  run_check desktop cargo test -p bibavpn-desktop --locked
fi
if [[ "$core" == true ]]; then
  run_check core cargo test -p bibavpn -p biba --locked
fi
if [[ "$mobile" == true ]]; then
  run_check mobile cargo test -p bibavpn-jni -p bibavpn-ffi --locked
fi
if [[ "$core$desktop$mobile" == falsefalsefalse ]]; then
  echo 'No Rust/UI paths changed; no matching crate tests.' >> "$work/TEST.log"
fi
exit "$result"
