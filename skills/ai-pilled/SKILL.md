# ai-pilled: Full-Stack Automation Skill

**Transforms your Code Agent into a lazy-engineer's dream: intelligent agents running security reviews, code audits, git validation, and workflow automation—all automatic, zero prompts.**

## What It Does

Wires up a complete automation stack where every tool use, git command, and code edit triggers specialized agent reviewers:

- **Security audits** on every file edit (basics, secrets, env leaks)
- **Code reviews** on commits (message clarity, aligned changes, obvious bugs)
- **Pre-push validation** (branch check, secrets scan, conventions)
- **Vulnerability audits** on dependencies
- **Batch summarizers** after tool chains (suggests next action)
- **Background test runners** on commits
- **Repo state loader** on session start

All with **zero permission prompts** — agents have blanket permissions.

## Installation

### Option 1: OpenCode (Recommended)
```bash
# In your Claude Code project
cd /path/to/project
opencode install ai-pilled
# Then type: /ai-pilled
```

### Option 2: Manual (Editable)
```bash
# Clone into ~/.claude/skills/
git clone https://github.com/tkarcheski/ai-pilled ~/.claude/skills/ai-pilled
```

## Quick Start

### 1. Enable the Skill
```bash
/ai-pilled
```

The ruleset applies to your session. Automation starts immediately.

## Core Workflows

### "I edited some files, make them perfect"
Every save triggers:
1. Security auditor (checks for XSS, SQL injection, secrets)
2. Type checker (if configured)
3. Linter suggestions

### "Ready to commit?"
Every commit triggers:
1. Code reviewer (checks message, changes alignment, obvious bugs)
2. Background test runner (async)

### "About to push?"
Every push triggers:
1. Pre-flight validator (branch, secrets, conventions)
2. If GitHub MCP configured: auto-creates PR

### "Should I refactor this?"
```bash
1. Delete unnecessary (requirements audit)
2. Delete part or process
3. Simplify & optimize (only what survived)
4. Accelerate cycle time
5. Automate (last)

## Settings

The skill auto-configures `~/.claude/settings.json` with:
- **Model**: Haiku (fast, cheap)
- **Hooks**: 7 agent hooks on common tools
- **Permissions**: Blanket allow (no prompts)

### Customize
Edit `~/.claude/settings.json` to:
- Change hook timeouts (faster = less thorough)
- Add async hooks (don't block on results)
- Disable specific matchers

Example: Make security audits non-blocking
```json
"async": true
```

## GitHub MCP (Optional)

Enable auto-PR creation and agent comments on PRs:

```bash
export GITHUB_TOKEN="ghp_your_token"
# Restart Claude — MCP loads automatically
```

## Environment

Set once, reuse everywhere:
```bash
export GITHUB_TOKEN="ghp_xxxx"
export CLAUDE_CODE_DISABLE_HOOKS=1  # Disable hooks temporarily
```

## Disable the Skill

```bash
# Temporary (this session only)
export CLAUDE_CODE_DISABLE_HOOKS=1

# Permanent
# Edit ~/.claude/settings.json, remove hooks block
```

## The Philosophy

**Lazy engineering wins.** You should:
- Write code
- Save
- Agents validate
- Push
- Agents review
- Never think about linting, testing, or conventions again

The machine does quality control. You do thinking.

## Result

You ship better code, faster, with less mental overhead. Every commit has been reviewed. Every push validated. Every file audited for security. All automatic.

**You are now full AI-pilled.** 🤖
