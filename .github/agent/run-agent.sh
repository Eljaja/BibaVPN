#!/usr/bin/env bash
# Run Cursor CLI with a staged permission file. Git/PR stay in the workflow.
set -euo pipefail

stage="${1:?stage: spec|implement|review}"
model="${2:?model slug}"
prompt_file="${3:?prompt markdown}"

root="$(cd "$(dirname "$0")/../.." && pwd)"
perm="$root/.github/agent/permissions/${stage}.json"
if [[ ! -f "$perm" ]]; then
  echo "missing permissions: $perm" >&2
  exit 1
fi
if [[ ! -f "$prompt_file" ]]; then
  echo "missing prompt: $prompt_file" >&2
  exit 1
fi
if [[ -z "${CURSOR_API_KEY:-}" ]]; then
  echo "CURSOR_API_KEY is empty" >&2
  exit 1
fi
# GitHub masks secrets.* ; still pin it in case a tool echoes the value.
if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
  echo "::add-mask::${CURSOR_API_KEY}"
fi

mkdir -p "$HOME/.cursor" "$root/.github/agent/work"
python3 - "$perm" <<'PY'
import json, pathlib, sys
perm = json.loads(pathlib.Path(sys.argv[1]).read_text())
cfg_path = pathlib.Path.home() / ".cursor" / "cli-config.json"
cfg = {}
if cfg_path.exists():
    try:
        cfg = json.loads(cfg_path.read_text())
    except json.JSONDecodeError:
        cfg = {}
cfg["permissions"] = perm["permissions"]
cfg_path.write_text(json.dumps(cfg, indent=2) + "\n")
PY

prompt="$(cat "$prompt_file")"
if [[ -n "${AGENT_EXTRA_PROMPT:-}" ]]; then
  prompt+=$'\n\n'"$AGENT_EXTRA_PROMPT"
fi

# --force: print mode otherwise only proposes edits.
# Transcript stays in $RUNNER_TEMP — not CI logs, not the PR.
log="${RUNNER_TEMP:-/tmp}/cursor-agent-${stage}.log"
set +x
if agent -p --force --model "$model" --output-format text "$prompt" >"$log" 2>&1; then
  echo "agent ${stage}: ok"
  exit 0
fi
echo "::error::agent ${stage} failed (transcript omitted)"
exit 1
