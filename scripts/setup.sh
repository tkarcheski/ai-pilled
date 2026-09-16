#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "--help" ]]; then
  echo "Usage: bash scripts/setup.sh [target-repository]"
  echo "Installs project-local Git and Codex hooks. Review Codex hooks with /hooks."
  exit 0
fi
if (( $# > 1 )); then
  echo "Expected at most one target repository." >&2
  exit 2
fi
case "${LLM_PROVIDER:-codex}" in
  codex|openai) ;;
  *) echo "Only the Codex adapter is verified. Other provider setup is not implemented." >&2; exit 2 ;;
esac

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
target="${1:-$PWD}"
python "$script_dir/ai-pilled.py" --repo "$target" install-git-hooks
python "$script_dir/ai-pilled.py" --repo "$target" install-codex-hooks
echo "Hooks installed. Review and trust the project hooks with /hooks in Codex."
echo "Configure test and other commands in the target's .ai-pilled.json."
echo "Ignore .ai-pilled/ in the target repository; it contains local reports."
