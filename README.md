# ai-pilled

Codex-first quality checks for Git repositories. ai-pilled uses itself as its first target.

The approved backlog is preserved in [docs/FEATURES.md](docs/FEATURES.md). The initial
prototype's installation and provider claims were not reliable. The list below describes
the running implementation, not the entire backlog.

## Use it

Requires Linux, Python 3.10+, and Git. Model review additionally requires a logged-in
Codex CLI. The Python runtime has no third-party dependencies.

From this repository:

~~~sh
python -m ai_pilled scan --scope worktree
python -m ai_pilled scan                    # reads the index, including partial staging
python -m ai_pilled dependency-audit        # npm lockfile vulnerability report
python -m ai_pilled check test
python -m ai_pilled review                  # subscription-backed, read-only staged review
~~~

Use `review --codex /absolute/path/to/codex` to select an installed binary explicitly.
This avoids PATH wrappers that install or update the CLI before each invocation. The
reviewer uses the existing Codex login, disables hooks, and receives a copy of staged
regular files plus the diff; missing results and timeouts are incomplete.

Commands emit JSON. Exit codes: **0** passed, **1** found blockers, **2** incomplete or
unable to run. Missing tools and missing configuration do not count as passing.

Configure the target repository in .ai-pilled.json:

~~~json
{
  "version": 1,
  "commands": {
    "test": ["python", "-m", "unittest", "discover", "-s", "tests", "-v"],
    "lint": ["ruff", "check", "."]
  },
  "protected_branches": ["main", "master"],
  "require_tests": true,
  "timeout": 120,
  "aggressiveness": "normal"
}
~~~

Commands are argument arrays, never shell strings. Configure only commands you trust.
Supported check names are test, lint, typecheck, deadcode, coverage, and dependency.
These commands report the configured tool's result; they do not invent coverage numbers
or dependency vulnerability data.

## Dependency vulnerabilities

Run `dependency-audit` in an npm project with package.json and a lockfile. It parses
npm audit v2 JSON, reports affected packages and fix availability, and invalidates
results if dependency inputs change during the audit. It includes development,
optional, and peer dependencies. Use `--npm /path/to/npm` to select the executable.

This command contacts your configured npm registry with dependency metadata, as
[documented by npm](https://docs.npmjs.com/cli/v11/commands/npm-audit/). It does not
install packages, run lifecycle scripts, or apply fixes. Registry errors and missing
lockfiles produce incomplete results. This checks known vulnerabilities only;
license policy, outdated packages, version conflicts, other package managers, and
automatic install-event auditing are separate pending features.

## Install hooks

~~~sh
python -m ai_pilled --repo /path/to/project install-git-hooks
python -m ai_pilled --repo /path/to/project install-codex-hooks
~~~

Git installation refuses to replace an existing hook manager or executable hooks.
Linked worktree installation uses worktree-specific Git configuration. Keep this source
checkout available: generated hook commands reference its Python runtime.

Codex installation merges project-local .codex/hooks.json entries. **Review and trust
the hooks with /hooks in Codex before expecting them to run.** Installation does not
bypass Codex permissions or hook trust. See the
[official hook documentation](https://learn.chatgpt.com/docs/hooks).

~~~sh
python -m ai_pilled --repo /path/to/project uninstall-codex-hooks
python -m ai_pilled --repo /path/to/project uninstall-git-hooks
~~~

Uninstall preserves unrelated hooks and refuses to erase user-modified owned hooks.
Local reports live in .ai-pilled/; add that directory to the target's .gitignore.

## What runs today

| Trigger | Behavior |
| --- | --- |
| Git pre-commit | Scan the exact staged blobs for recognizable credential patterns |
| Git commit-msg | Validate conventional subject format and a 72-character limit |
| Git pre-push | Protect destination branches, scan outgoing commit snapshots, run required tests |
| Codex session start | Load branch and working-tree status |
| Codex post-tool | Scan working-tree credentials and report findings |
| Codex stop | Run configured tests; request one repair pass if they fail |
| Explicit review | Ask Codex to review the staged diff with a strict result schema |

Pre-push tests require a clean working tree and the pushed commit checked out at HEAD.
A secret removed in a later outgoing commit is still caught. More than 2,000 outgoing
commits requires a smaller audited range. Files larger than 2 MB produce an incomplete
scan, not a clean bill of health.

Credential matching is a limited deterministic check, not a complete security audit.
Semantic code review is currently explicit; automatic model review on every commit,
coverage thresholds, performance baselines, release
workflows, notifications, and other backlog items are still being implemented.
The aggressiveness setting is validated but does not yet select different pipelines.
Claude Code, OpenCode, and Pi integrations are not verified.

## Recorded evidence

`summary` returns one sentence, unresolved checks, a proceed/wait indicator, and the
next step from the latest recorded result for each check. No history means wait.
`dashboard` writes an offline HTML view to .ai-pilled/dashboard.html, including the
latest 100 runs. It escapes findings and loads no external scripts or assets.

Explicit scans, configured checks, Git gates, lifecycle hooks, model reviews, and npm
audits record local results. These are historical observations: a green dashboard
does not certify files changed since the checks ran. Summaries do not read or store
raw tool output, and they do not invent a successful check when evidence is absent.

## Development

~~~sh
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests -v
python -m ai_pilled check test
~~~

Tests exercise actual commits and pushes against disposable repositories, isolate inherited
Git environment variables, and use a fake Codex executable for deterministic provider failure
tests. Live Codex validation is reported separately; a fake-provider test is not proof of
account access or model quality.

MIT license.
