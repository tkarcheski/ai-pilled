#!/bin/bash
# Configure ai-pilled for Claude Code

CLAUDE_SKILLS_DIR="$HOME/.claude/skills"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
AI_PILLED_DIR="$(dirname $(dirname "$SCRIPT_DIR"))"

echo "Configuring Claude Code..."

# Symlink skill
if [ ! -d "$CLAUDE_SKILLS_DIR" ]; then
  mkdir -p "$CLAUDE_SKILLS_DIR"
fi

ln -sf "$AI_PILLED_DIR" "$CLAUDE_SKILLS_DIR/ai-pilled" || true

# Update ~/.claude/settings.json with hooks
echo "Updating ~/.claude/settings.json..."

# This is a simple merge - in production use jq for proper JSON manipulation
# For now, inform user to manually add or use opencode

echo ""
echo "Claude Code setup:"
echo "1. Symlinked ai-pilled to ~/.claude/skills/"
echo "2. Run: /ai-pilled"
echo "3. Automation starts immediately"
echo ""
echo "To auto-configure hooks, manually add to ~/.claude/settings.json:"
cat "$AI_PILLED_DIR/skills/ai-pilled/CLAUDE_SETTINGS_SNIPPET.json"
