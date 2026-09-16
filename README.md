# ai-pilled 🤖

> **Full-stack automation for engineers who hate thinking about tooling.**
>
> Intelligent agents automatically review your code for security, validate git operations, run tests, audit dependencies, and suggest next steps. All automatic. All fast. All configurable.

## What Is This?

A **skill** that transforms any LLM-powered IDE into an automated code-quality machine:

- Every file edit → Custom Security audit
- Every commit → Code review + async test runner
- Every push → Pre-flight validation (secrets, conventions, branch)
- Every dependency install → Vulnerability audit
- Every tool batch → Summarizer suggests next action
- Session start → Load repo state

**Result**: You write code. Agents handle quality control. You never think about linting, testing, or conventions again.

## Quick Start

### Claude Code
```bash
# Clone into skills directory
git clone https://github.com/tkarcheski/ai-pilled ~/.claude/skills/ai-pilled

# Or install via OpenCode
cd /path/to/project
opencode install ai-pilled

# Then activate
/ai-pilled
```

### Any Other LLM (Generic)
```bash
# Clone anywhere
git clone https://github.com/tkarcheski/ai-pilled
cd ai-pilled

# Run setup helper
bash scripts/setup.sh

# Configure for your LLM
export LLM_PROVIDER="openai"  # or "anthropic", "generic"
export LLM_API_KEY="your_key_here"

# Apply the ruleset manually (add to your LLM's system prompt)
cat skills/ai-pilled/SYSTEM_PROMPT.txt
```

## Installation by Provider

### Claude Code (Official)
```bash
# Option A: Via OpenCode
opencode install ai-pilled
/ai-pilled

# Option B: Manual (Editable Setup)
git clone https://github.com/tkarcheski/ai-pilled ~/.claude/skills/ai-pilled

# Auto-configures ~/.claude/settings.json with hooks
```

### OpenAI (ChatGPT, GPT-4)
```bash
export OPENAI_API_KEY="sk_..."
export LLM_PROVIDER="openai"

# Configure your system prompt with:
cat skills/ai-pilled/SYSTEM_PROMPT.txt

# Then use in GPT with custom instructions
```

### Anthropic Console
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
export LLM_PROVIDER="anthropic-console"

# Use the system prompt from:
cat skills/ai-pilled/SYSTEM_PROMPT.txt
```

### Generic/Any Other LLM
```bash
export LLM_PROVIDER="generic"
export LLM_ENDPOINT="https://your-llm-api.com/v1/messages"
export LLM_API_KEY="your_key"

# Apply system prompt to your LLM's setup
```

## Core Features

### 1. **Security Auditor Agent**
Runs on every file edit. Checks for:
- Hardcoded secrets (AWS keys, tokens)
- Environment variable leaks
- Unsafe crypto/parsing patterns

### 2. **Code Reviewer Agent**
Runs on every `git commit`. Checks:
- Commit message clarity (conventional commits)
- Changes align with message
- Obvious bugs or logic errors
- Dead code or unused imports

### 3. **Pre-Push Validator Agent**
Runs on every `git push`. Validates:
- Pushing to correct branch
- No secrets in commits
- Follows project conventions
- Tests passed (if configured)

### 4. **Dependency Auditor Agent**
Runs on `npm install`, `yarn add`, etc. Audits:
- Known vulnerabilities (CVE)
- Outdated or security-critical updates
- Conflicting versions
- License compliance

### 5. **Batch Summarizer Agent**
Runs after every tool chain. Provides:
- One-sentence summary (what just happened)
- Any errors or warnings
- Next logical step
- Blocker status (proceed or wait)

## Quick Commands

```bash
# Activate the skill (this session)
/ai-pilled

# Run full pipeline: lint → test → commit → push → PR
bash ~/.claude/automation/lazy-flow.sh

# Watch agents in real-time
watch -n 1 'bash ~/.claude/automation/agent-status.sh'

# Background code review
claude --bg /code-review ultra

```

## Workflows

### "I just edited stuff, make it production-ready"
```bash
# Auto-runs on save:
# 1. Security audit
# 2. Type check (if configured)
# 3. Lint suggestions
```

### "Ready to commit?"
```bash
git commit -m "your message"
# Auto-runs:
# 1. Code review (message clarity, aligned changes)
# 2. Background test runner
```

### "Ready to push?"
```bash
git push
# Auto-runs:
# 1. Pre-flight validation (branch, secrets, conventions)
# 2. Auto-creates PR (if GitHub MCP configured)
# 3. Posts agent review as PR comment
```

### "Should I refactor this module?"
```bash
# Runs 5-step audit:
# 1. Audit requirements (owner clarity)
# 2. Delete the part (delete 90%+)
# 3. Simplify (optimize survivors)
# 4. Accelerate cycle time
# 5. Automate (last)
```

## Configuration

### Claude Code
Edit `~/.claude/settings.json`:
```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Edit",
        "hooks": [{
          "type": "agent",
          "prompt": "Security audit...",
          "timeout": 15
        }]
      }
    ]
  }
}
```

### Any Other LLM
```bash
# 1. Copy system prompt
cat skills/ai-pilled/SYSTEM_PROMPT.txt

# 2. Apply to your LLM's config/instructions
# For OpenAI: Custom instructions
# For Anthropic: System prompt
# For others: Prepend to conversation

# 3. Set environment
export LLM_PROVIDER="your_provider"
export LLM_API_KEY="your_key"
```

## Customization

### Aggressiveness Levels

**Lazy** (fewer checks, faster):
```bash
export AGGRESSIVENESS="lazy"
```
- Only critical security checks
- Commit message validation only
- No performance audits

**Normal** (default):
```bash
export AGGRESSIVENESS="normal"
```
- Full security audit
- Code review + tests
- Dependency checks

**Strict** (everything):
```bash
export AGGRESSIVENESS="strict"
```
- Full security audit
- Code review + tests + coverage
- Dependency audits + licenses
- Performance regressions

### Enable GitHub Integration
```bash
export GITHUB_TOKEN="ghp_your_token"
export ENABLE_GITHUB_INTEGRATION=true
# Agents auto-create PRs and post reviews
```

### Enable Slack Notifications
```bash
export SLACK_WEBHOOK="https://hooks.slack.com/..."
export ENABLE_SLACK_NOTIFICATIONS=true
# Agent findings post to Slack
```

## Default Automations

### Tier 1: Merge Requests 
1. Dead code detector
2. Type safety verifier
3. Dependency health checker
4. Commit message validator
5. Branch protector

### Tier 2: Nightly/Release
6. Test coverage auditor
7. Performance regression detector
8. Bundle size watcher
9. Changelog auto-generator
10. README updater

### Tier 3: Weekly/Planning
11. Full audit workflow (parallel agents)
12. PR-ready checker
13. Release flow automation
14. Refactor flow (simplify → fix → test)

### Tier 4: Instant Integrations
15. Slack notifications
16. Linear ticket creation
17. GitHub auto-comments
18. Email digests
19. Metrics dashboards

### Roadmap Experimental Features
20. Semantic release (auto-version)
21. Trunk-based dev (auto-merge)
22. AI bug bounty (find issues)
23. Nightly refactoring
24. Self-healing (auto-revert breaks)

## Agent Feature Comparison: Provider Support (PENDING VERIFICATION)

| Feature | Claude Code | OpenAI | OpenCode | Pi-Code-Agent |
|---------|------------|--------|-----------|---------|
| Security audits |  |  |  |  |
| Code reviews |  |  |  |  |
| Git validation |  |  |  |  |
| Auto hooks |  |  |  |  |
| GitHub integration |  |  |  |  |
| Slack notifications |  |  |  |  |
| Background agents |  |  |  |  |
| Status line |  |  |  |  |

## FAQ: How Disable (OR PAUSE) Everything

```bash
# Temporary (this session)
export CLAUDE_CODE_DISABLE_HOOKS=1
claude

# Permanent (any provider)
unset ENABLE_AI_PILLED
# Remove system prompt from your LLM config
```

## Philosophy

> **Ship better code faster, by not thinking about tooling.**

You write code. The machine validates quality. You never manually run linters, write tests, or think about conventions.

**Result**: Every commit has been reviewed. Every push validated. Every file audited for security. All automatic.

## Support

- **Claude Code users**: See `skills/ai-pilled/SKILL.md`
- **OpenCode users**: See `opencode.json` and `skills/ai-pilled/SYSTEM_PROMPT.txt`
- **Generic LLM users**: See `scripts/setup.sh` and `skills/ai-pilled/PROMPTS.json`
- **Ideas to add**: See `automation/README.md`
- **Command reference**: See `automation/QUICK-REF.md`

## License

MIT — Use freely, modify, share.

---

**You are now full AI-pilled.** Enjoy your lazy engineering life. 🚀
