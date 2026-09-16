---
name: ai-pilled
description: Run repository quality checks, staged code review, and Git readiness checks with ai-pilled. Use when the user asks to enable ai-pilled, audit proposed changes, or prepare commits and pushes in a configured repository.
---

# ai-pilled

Locate the runtime at ../../scripts/ai-pilled.py relative to this skill's directory.
Pass the intended Git repository with --repo; do not assume the shell's working
directory is the target.

Use "scan --scope worktree" after edits, "scan" for the actual index, and "check test"
for the repository's configured test command. "review" sends the staged diff to a
read-only Codex process using the user's existing CLI login.

Read JSON results and preserve the difference between pass, fail, and incomplete.
An unavailable provider, missing command, or oversized file has not passed.
The deterministic credential scan does not establish general code security.
Tests of the working tree do not prove different staged or historical code works.

Configure checks in the target's .ai-pilled.json using argument arrays. Do not
invent test commands, coverage measurements, vulnerability findings, or provider
capabilities. Read the target's actual conventions and manifests.

Install Git or Codex hooks only when requested or authorized by the setup task.
Preserve existing hooks. Codex hook installation is separate from activation:
tell the user to review the actual definitions with /hooks.
Never change approval policy or claim prompts alone create automatic hooks.

Before a commit, inspect the staged diff and run the relevant checks. Stage only
the intended files. Follow explicit shared-workspace ownership and board protocols.
Push, publish, release, and notification actions must stay within the user's scope.

For feature support and limitations, read the source repository's README.md.
