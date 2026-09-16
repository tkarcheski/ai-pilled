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
The benchmark command uses a separate commands.benchmark argument array.
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
other package managers and automatic install-event auditing remain pending.

`dependency-health` checks the installed tree with npm ls and queries available
versions with npm outdated. Invalid/missing dependencies block; newer versions are
informational and are not labeled vulnerabilities. It does not install or update packages.

`licenses --allow MIT --allow Apache-2.0` compares declared license expressions in
npm lockfile v2/v3 package metadata against your exact allowlist. Missing metadata is
incomplete; expressions outside the list fail. Compound expressions must be allowed
explicitly in their complete form. This is a metadata policy check, not a determination
of legal compliance or verification of package license files.

## Review commits with Codex

Set review_on_commit to true in .ai-pilled.json to require a passing structured Codex
review from the commit-msg hook. Set codex_executable to an installed executable path
when your PATH command is an auto-update wrapper. The default is opt-out; enabling
this uses your Codex subscription on commits and may block on timeout or unavailable
login. Explicit review also honors codex_executable; --codex overrides it.

The reviewer receives the staged diff and proposed message to check correctness and
message alignment. A conventional-message or credential failure blocks before model
inference. Commit bodies are scanned locally, and outgoing commit messages are also
scanned before push. Empty staged diffs do not invoke the model; amendment semantics
for existing changes are not inferred. Hooks do not grant permissions or bypass trust.

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
| Git commit-msg | Validate subject format, message credentials, and optional Codex review |
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
Semantic review examines staged diffs; release
workflows, notifications, and other backlog items are still being implemented.
Claude Code, OpenCode, and Pi integrations are not verified.

## Quality profiles and local PR readiness

~~~sh
python -m ai_pilled quality
python -m ai_pilled ready
~~~

Both commands run the configured aggressiveness profile and return individual check
results plus an aggregate status. lazy runs credential scanning and required/configured
tests. normal also runs configured lint, typecheck, deadcode, coverage, and dependency
commands; with an npm lockfile and no custom dependency command, it uses the npm
auditor. strict additionally requires explicit lint, typecheck, deadcode, coverage,
and test commands. Missing required commands remain incomplete.

Checks run sequentially because project commands can share build artifacts. A
credential failure stops command execution. A changed source snapshot or HEAD during
checks invalidates the result. ready additionally requires a clean committed feature
branch, excluding protected branches and detached HEAD. It does not open a PR, attest
to remote CI, or automatically perform model review.

## Coverage and artifact budgets

~~~sh
python -m ai_pilled coverage --report coverage.json --minimum 80
python -m ai_pilled bundle --path dist --maximum 250000
~~~

Coverage reads [coverage.py JSON](https://coverage.readthedocs.io/en/latest/commands/cmd_json.html)
and computes line coverage from covered/total counts, without trusting rounded
percentages. Generate the report from the current code first; this command evaluates
the supplied report and does not run tests or prove freshness. Empty or invalid
reports are incomplete. Branch coverage is not evaluated yet.

Bundle checks measure the raw bytes of a built file or directory, hash its contents,
and compare the total against the explicit byte budget. Build first. Missing/empty
artifacts, symlinks, or inputs above the 100 MB measurement limit are incomplete.
These commands record actual measurements alongside their pass/fail results.

## Performance regression checks

Configure commands.benchmark with an argument array for a representative workload:

~~~sh
python -m ai_pilled benchmark --save-baseline
python -m ai_pilled benchmark --maximum-regression 20 --runs 3
~~~

The first command explicitly records a local median duration; the second measures
again and fails if the median exceeds that baseline by more than 20%. Comparisons
never update the baseline. Missing baselines, changed commands or hosts, and failed
processes are incomplete. Baselines live in .ai-pilled/benchmark.json and do not
contain command arguments or raw output. Durations include process startup; choose
a stable workload and account for system load. This repo benchmarks its staged scanner.

## Changelog and version proposals

~~~sh
python -m ai_pilled release-plan --current 1.2.3 --since v1.2.3
~~~

The JSON result includes a grouped Markdown changelog, commit count, proposed version,
and the exact HEAD used. feat selects a minor bump; fix/perf selects patch; an exclamation
mark or BREAKING CHANGE footer selects major. Documentation-only or empty ranges do
not invent a release. Stable MAJOR.MINOR.PATCH versions are supported; prerelease
version rules are not yet implemented.

The base must resolve to an ancestor of HEAD. Without --since, all history is considered
(up to 1,000 commits). Notes escape Markdown/HTML and refuse commit messages containing
recognizable credentials. This command proposes metadata; it does not modify versions,
create tags, push, publish packages, or create a GitHub release.

## Generated README reference

Run update-readme to refresh one marked command-reference section without replacing
handwritten documentation. update-readme --check reports drift without writing the
file. Existing file permissions are preserved; malformed or duplicate markers and
symlink paths are rejected. The generated section lists configured check names, never
private command arguments or historical pass claims.

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

Install the pinned tools into the ignored project-local environment before running
the full quality profile:

~~~sh
python -m venv .ai-pilled/tools
.ai-pilled/tools/bin/python -m pip install -r requirements-dev.txt
python -m ai_pilled quality
~~~

The profile runs Ruff, mypy body checks, high-confidence Vulture checks, and a fresh
coverage run with an 80% line budget. These tools supplement review; they do not
prove the absence of dead code or type errors. The baseline tests remain dependency-free:

~~~sh
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests -v
python -m ai_pilled check test
~~~

Tests exercise actual commits and pushes against disposable repositories, isolate inherited
Git environment variables, and use a fake Codex executable for deterministic provider failure
tests. Live Codex validation is reported separately; a fake-provider test is not proof of
account access or model quality.

MIT license.

<!-- ai-pilled:commands:start -->
## ai-pilled command reference

Generated from the installed CLI and project check configuration.

Quality profile: **normal**. Configured commands: benchmark, coverage, deadcode, lint, test, typecheck.
Configuration is not proof that checks passed; use quality to run them.

~~~text
usage: ai-pilled [-h] [--repo REPO]
                 {scan,check,review,dependency-audit,coverage,bundle,benchmark,dependency-health,licenses,release-plan,update-readme,quality,ready,summary,dashboard,lifecycle,install-codex-hooks,uninstall-codex-hooks,install-git-hooks,uninstall-git-hooks,hook} ...

positional arguments:
  {scan,check,review,dependency-audit,coverage,bundle,benchmark,dependency-health,licenses,release-plan,update-readme,quality,ready,summary,dashboard,lifecycle,install-codex-hooks,uninstall-codex-hooks,install-git-hooks,uninstall-git-hooks,hook}
    scan                Scan the Git index or working tree for credentials
    check               Run a configured quality command
    review              Review the staged snapshot with Codex
    dependency-audit    Audit npm lockfile vulnerabilities
    coverage            Check line coverage from coverage.py JSON
    bundle              Check built artifacts against a byte budget
    benchmark           Compare median process time against a local baseline
    dependency-health   Check installed npm tree and available versions
    licenses            Match lockfile licenses against an explicit allowlist
    release-plan        Generate changelog and semantic-version proposal
    update-readme       Refresh a generated README command reference
    quality             Run the configured quality profile
    ready               Validate a clean proposal branch and its quality checks
    summary             Summarize recorded checks and next steps
    dashboard           Build an offline check-history dashboard

options:
  -h, --help            show this help message and exit
  --repo REPO
~~~
<!-- ai-pilled:commands:end -->
