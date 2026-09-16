#!/bin/bash
# Universal setup for ai-pilled (works with any LLM provider)

set -e

echo "🤖 ai-pilled Setup"
echo "================================"
echo ""

# Detect current provider or ask user
if [ -z "$LLM_PROVIDER" ]; then
  echo "Which LLM provider do you use?"
  echo "1) Claude Code (default)"
  echo "2) OpenAI (ChatGPT, GPT-4)"
  echo "3) Anthropic Console"
  echo "4) Generic / Other LLM"
  echo ""
  read -p "Enter choice (1-4): " choice

  case $choice in
    1) LLM_PROVIDER="claude" ;;
    2) LLM_PROVIDER="openai" ;;
    3) LLM_PROVIDER="anthropic" ;;
    4) LLM_PROVIDER="generic" ;;
    *) LLM_PROVIDER="claude" ;;
  esac
fi

echo "Provider: $LLM_PROVIDER"
echo ""

# Provider-specific setup
case $LLM_PROVIDER in
  "claude")
    echo "Setting up for Claude Code..."
    bash scripts/configure-claude.sh
    ;;
  "openai")
    echo "Setting up for OpenAI..."
    bash scripts/configure-openai.sh
    ;;
  "anthropic")
    echo "Setting up for Anthropic Console..."
    bash scripts/configure-generic.sh anthropic
    ;;
  "generic")
    echo "Setting up for Generic LLM..."
    bash scripts/configure-generic.sh
    ;;
esac

echo ""
echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "1. Add the system prompt to your LLM:"
echo "   cat skills/ai-pilled/SYSTEM_PROMPT.txt"
echo ""
echo "2. Enable automation:"
echo "   export ENABLE_AI_PILLED=1"
echo ""
echo "3. Try it out:"
echo "   bash automation/lazy-flow.sh"
echo ""
