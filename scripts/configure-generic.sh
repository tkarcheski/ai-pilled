#!/bin/bash
# Configure ai-pilled for generic LLM or Anthropic Console

PROVIDER=${1:-"generic"}

echo "Configuring ai-pilled for $PROVIDER..."
echo ""
echo "Manual Setup Steps:"
echo ""
echo "1. Copy the system prompt:"
echo "   cat skills/ai-pilled/SYSTEM_PROMPT.txt"
echo ""
echo "2. Add it to your LLM:"
if [ "$PROVIDER" = "anthropic" ]; then
  echo "   → Paste into Anthropic Console > System Prompt"
else
  echo "   → Add to your LLM's system prompt/instructions"
fi
echo ""
echo "3. Set environment variables:"
echo "   export ENABLE_AI_PILLED=1"
echo "   export LLM_PROVIDER=\"$PROVIDER\""
if [ "$PROVIDER" = "generic" ]; then
  echo "   export LLM_ENDPOINT=\"https://your-api.com/v1/messages\""
fi
echo "   export LLM_API_KEY=\"your_key_here\""
echo ""
echo "4. Try it:"
echo "   bash automation/lazy-flow.sh"
echo ""
echo "For more details, see README.md"
