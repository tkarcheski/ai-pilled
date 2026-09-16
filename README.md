# ai-pilled

Codex-first quality checks for Git repositories. ai-pilled uses itself as its first target.

The approved backlog is preserved in [docs/FEATURES.md](docs/FEATURES.md).
[Feature evidence and activation status](docs/STATUS.md) tracks what is implemented,
what was verified, and what still requires deployment. Use the commands and setup
flows below; provider support and activation requirements are explicit.

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

Run `python -m ai_pilled review-checks` to check the exact index in a disposable
copy. It always requires tests, lint, type checking, dead-code checks, and coverage,
even with a lazy profile. Missing commands are incomplete. Staged configuration is
used; unstaged source and fixes cannot make a staged defect pass. Source executables
come from that copy; untracked local tool installations may be reused from the original
checkout. Changes made by checks invalidate the result. Configured commands must be
trusted: this disposable copy is not an operating-system security sandbox.

`review --comprehensive` requires those checks to pass before invoking the model and
verifies that both stages reviewed the same index. `review-checks` runs without a model
or subscription call. Stage the intended files before using either command. Set
`"review_checks_on_commit": true` to require these checks in the pre-commit hook.
This repository enables it for dogfooding; model review remains a separate opt-in.

Use `review --codex /absolute/path/to/codex` to select an installed binary explicitly.
This avoids PATH wrappers that install or update the CLI before each invocation. The
reviewer uses the existing Codex login, disables hooks, and receives a copy of staged
regular files plus the diff; missing results and timeouts are incomplete.
Recognizable credentials in historical diff lines are redacted before model invocation.
Prepared blobs are rescanned, and an index change before invocation cancels the review.

Commands emit JSON. Exit codes: **0** passed, **1** found blockers, **2** incomplete or
unable to run. Missing tools and missing configuration do not count as passing.
Structured JSON inputs are limited to 100 nested containers; excessive nesting is
reported explicitly instead of producing a recursion traceback.
Reports retain up to 100 findings plus a truncation notice, prioritizing errors over
informational notices. Truncated reports remain blocking. Recognizable credentials
are redacted from reports, command errors, hook context, and legacy history views;
private-key redaction removes the body as well as its header.

Configure the target repository in .ai-pilled.json (a regular file, at most 64 KB;
symlinks and special files are rejected):

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

## Python dependency vulnerability audits

Run `python -m ai_pilled python-audit --requirements requirements-dev.txt --pip-audit /path/to/pip-audit`.
Repeat --requirements to audit multiple repository-relative files. The default is
requirements.txt. Install pip-audit separately in a virtual environment; the ai-pilled
runtime still has no third-party dependencies. This integration is tested with pip-audit 2.10.1.

Inputs must contain exact name==version pins, comments, and blank lines. Export a complete
resolved dependency set first: only the listed packages are audited, and missing transitive
pins cannot be inferred. URLs, editable installs, nested requirement files, options, extras,
markers, and version ranges are rejected explicitly. Requirements are bounded regular files;
recognizable credentials block before a provider is called.

The adapter supplies a sanitized snapshot to pip-audit with --no-deps, --disable-pip, and
--strict. It never installs, executes package build code, or applies fixes. Package names
and versions are queried against PyPI's advisory service. Every selected package must
appear exactly once in the returned evidence; skipped/missing packages, malformed results,
timeouts, and changed inputs make the audit incomplete. Known advisories block and report
available fixed versions. See the [official pip-audit documentation](https://github.com/pypa/pip-audit).

## Python environment health and licenses

Run `python -m ai_pilled python-health --python .venv/bin/python` to inspect a trusted
Python environment and check missing/incompatible dependencies. Pip23+ with inspect
JSON version1 is required. Python isolated mode prevents project-local modules and
PYTHONPATH from impersonating pip; user-site packages are excluded. No packages are
installed or upgraded. The selected interpreter and its existing startup hooks must be trusted.

Add --outdated for explicit PyPI version queries using pip25.1+ index JSON support.
Every installed package needs confirmed compatible release evidence within the overall
query timeout. An unavailable index, unknown package, unsupported pip, changed environment,
or installed version absent from public releases yields an incomplete result. This avoids
pip list --outdated's empty-success behavior when its index is unavailable. Update notices
are informational; dependency conflicts block. Local-only health checks make no registry queries.

Run `python -m ai_pilled python-licenses --python .venv/bin/python --allow MIT` with your
own explicit policy. Repeat --allow for more expressions. Checks prefer License-Expression
metadata, then bounded legacy License text; expressions must match exactly. Missing,
unknown, or prose-only metadata needs manual review. This checks declarations, not legal
compatibility, and includes tooling installed in the selected environment.

See pip's [inspect schema](https://pip.pypa.io/en/stable/reference/inspect-report/),
[dependency check](https://pip.pypa.io/en/stable/cli/pip_check/), and
[version lookup](https://pip.pypa.io/en/stable/cli/pip_index/) documentation.

## Publish verified release metadata

After preparing and committing VERSION/CHANGELOG.md, create and push the intended tag
through your normal Git review process. Run publish-release with --github-repo OWNER/REPO,
--tag vMAJOR.MINOR.PATCH, and --expected-head FULL-COMMIT-SHA to preview publication.
It requires a clean committed checkout, matching VERSION, one exact changelog section,
passing quality gates, and local and remote tags resolving to the same selected commit.
The preview reads GitHub but does not create a release.

Only --publish creates the public GitHub release. Notes are scanned for recognizable
credentials and passed through standard input. Tags are never created or moved by this
command; --verify-tag prevents implicit tag creation. The resulting tag, notes, and
published state are checked, and ambiguous outcomes require inspection before retrying.
This publishes release notes, not package-registry artifacts. GitHub.com and stable
versions are supported. --gh selects an installed GitHub CLI. See the
[official release creation reference](https://cli.github.com/manual/gh_release_create).
Tests use real disposable Git repositories and fake GitHub responses; no real release
has been published as part of implementation.

## GitHub auto-merge (experimental)

Use auto-merge with --github-repo OWNER/REPO, --pr NUMBER, --base BRANCH, and
--expected-head FULL-COMMIT-SHA to inspect an exact PR. This preview reads GitHub but
does not mutate it. The PR must be open, non-draft, approved, and confirmed mergeable.
At least one required CI check must exist; passing and pending checks are acceptable,
while failures, cancellation, skipped checks, or unknown evidence block the request.

Only --enable requests GitHub squash auto-merge. It re-reads the PR immediately before
requesting, pins the head using --match-head-commit, and checks the resulting server
state. **Enabling may merge immediately if all requirements pass.** GitHub branch
protections remain authoritative; no admin bypass or branch deletion is used. Unknown
outcomes require inspection before retrying. This does not configure branch protections,
create PRs, or grant approval. GitHub.com is supported; enterprise hosts are not yet.

The command uses your GitHub CLI login. Select --gh /absolute/path/to/gh if your PATH
command wraps an installer or updater. See the official
[GitHub CLI merge reference](https://cli.github.com/manual/gh_pr_merge) and
[required-check reference](https://cli.github.com/manual/gh_pr_checks).
Provider behavior is tested with fake CLI responses, including changed heads and
unconfirmed outcomes. No real repository auto-merge was enabled during development.

## Verified self-healing (experimental)

Run `python -m ai_pilled heal --expected-head FULL-COMMIT-SHA` to investigate a failing
latest commit. The command requires a clean branch, one parent, a configured test,
and a passing credential/security scan. It first establishes that current tests fail,
then reverses that commit in a disposable clone and runs the entire quality profile.
After the candidate passes, the original tests run again to confirm the failure still
reproduces. Passing or unavailable confirmation produces no patch or revert. A verified
candidate with a repeated original failure produces a private patch; the original
checkout is unchanged.
Passing current tests need no action. Merge commits, changed quality policies, and
still-failing candidates require manual review.

Add --apply only when you intend to create a local revert commit. It rechecks the exact
HEAD, branch, and clean checkout, runs ordinary Git hooks, uses a conventional fix
message, and verifies the resulting tree against the tested candidate. It never resets
history or pushes. If a hook or Git operation fails, changes may remain staged and the
result requests checkout inspection; it does not discard that work. Use exclusive access
to the checkout while applying. This is an explicit command, not an active repair daemon.
The failure/recovery paths and real Git revert commits are tested in disposable fixtures.

## Full audit and bug finding

Run `python -m ai_pilled full-audit` for the configured quality profile. Adding
--model-reviews explicitly starts three subscription-backed Codex reviews focused on
correctness, security, and maintenance. Use --workers 1 to run those perspectives
sequentially, or up to three workers for concurrent reviews. --codex selects an installed
CLI binary. The default command makes no model calls.

Model audits require passing quality gates and a clean committed checkout. Each reviewer
gets its own regular-file snapshot (20 MB maximum), the read-only Codex sandbox, disabled
hooks, and an allowlisted environment. Missing reviewers and malformed output are
incomplete; defects retain their file/line evidence. Source or index changes invalidate
results. Model findings need engineering review and do not prove the absence of bugs.
This is a local issue-finding workflow; it does not submit bounty reports or create tickets.
Concurrency and failure handling are tested with fake reviewers. No model audit workers
have been launched as part of this development session.

## Explicit notifications

The notify command previews a minimal digest of recorded results. Findings, source,
file paths, and command output are omitted. Preview requires no credentials or network.
Select the destination explicitly, inspect the preview, then add --send to deliver:

~~~sh
python -m ai_pilled notify slack
python -m ai_pilled notify github --github-repo OWNER/REPO --issue 123
python -m ai_pilled notify linear --team TEAM-UUID
python -m ai_pilled notify email --sender you@example.com --recipient team@example.com
~~~

Delivery uses environment variables, never credentials in project configuration:

| Provider | Environment variables | Action with --send |
| --- | --- | --- |
| Slack | AI_PILLED_SLACK_WEBHOOK | Post to its configured channel |
| GitHub | AI_PILLED_GITHUB_TOKEN | Create an issue or PR comment |
| Linear | AI_PILLED_LINEAR_KEY (personal API key) | Create an issue in the selected team |
| Email | AI_PILLED_SMTP_HOST, AI_PILLED_SMTP_USER, AI_PILLED_SMTP_PASSWORD; optional AI_PILLED_SMTP_PORT (465) | Submit a plain-text digest using authenticated SMTP over TLS |

Adapters follow the official [Slack incoming webhook](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/),
[GitHub issue comment](https://docs.github.com/en/rest/issues/comments#create-an-issue-comment),
and [Linear GraphQL](https://linear.app/developers/graphql) APIs. HTTP delivery does not
follow redirects. Responses are bounded and raw provider diagnostics are not displayed.
An accepted result confirms provider acceptance, not human receipt. There are no automatic
retries or duplicate suppression: repeated sends can create duplicate messages or issues.
After an unconfirmed result, inspect the destination before retrying. No notifications are
sent by hooks, and no schedule is installed. Transport behavior is tested with fakes;
credentials and delivery to a real recipient must be verified separately.

## Nightly refactoring (explicit foreground mode)

After configuring and verifying refactor, run nightly-refactor --at 03:00 --timezone
America/Chicago for one due-time check. Before that local wall time it waits; at or after
it, the command attempts one refactor per calendar date. It exports verified patches
through the same disposable workflow and never applies, commits, or pushes them.

Add --watch to keep checking once per minute in the foreground until Ctrl-C. This does
not install a daemon, cron entry, system service, or Codex automation. Nothing recurs
unless that foreground process is deliberately started and kept running. Missed dates
are not replayed. A skipped spring-forward time runs after the clock jumps ahead; the
repeated fall-back hour does not run twice.

Attempts are serialized with a nonblocking repository lock and recorded before work.
Restarting after failure or interruption does not silently repeat that day's commands.
Inspect the prior result and any generated patch before using --retry for a deliberate
same-day retry. Changing the time or timezone selects a separate schedule. Schedule state
and patches stay under ignored .ai-pilled/. Tests use controlled clocks and fake refactors;
no recurring process is active as part of this repository's setup.

## Refactor in a disposable checkout

Configure commands.simplify and commands.repair as trusted argument arrays, plus
commands.test, then run `python -m ai_pilled refactor` from a clean committed checkout.
The workflow runs simplify, repair, credential checks, and the configured quality profile
in a temporary local clone. It exports a private patch under the ignored .ai-pilled/
directory only after all gates pass. Review and apply that patch explicitly; the workflow
does not modify the source checkout, commit, push, or schedule itself.

This repository configures Ruff unused-import cleanup for simplify and safe Ruff fixes
for repair; the strict quality profile validates the result. These are deterministic
cleanup steps and do not launch another model.

Commands cannot change HEAD or the quality configuration. Relative executable paths
may use the source checkout's local tools, preserving virtual environments; command
arguments resolve inside the clone. This separates working copies, but is not a security
sandbox: trusted commands still have your normal filesystem and network access.

## Dependency vulnerabilities

Run `dependency-audit` in an npm project with package.json and a lockfile. It parses
npm audit v2 JSON, reports affected packages and fix availability, and invalidates
results if dependency inputs change during the audit. It includes development,
optional, and peer dependencies. Use `--npm /path/to/npm` to select the executable.

This command contacts your configured npm registry with dependency metadata, as
[documented by npm](https://docs.npmjs.com/cli/v11/commands/npm-audit/). It does not
install packages, run lifecycle scripts, or apply fixes. Registry errors and missing
lockfiles produce incomplete results. This checks known vulnerabilities only;
other package managers remain pending.

`dependency-health` checks the installed tree with npm ls and queries available
versions with npm outdated. Invalid/missing dependencies block; newer versions are
informational and are not labeled vulnerabilities. It does not install or update packages.

`licenses --allow MIT --allow Apache-2.0` compares declared license expressions in
npm lockfile v2/v3 package metadata against your exact allowlist. Missing metadata is
incomplete; expressions outside the list fail. Compound expressions must be allowed
explicitly in their complete form. This is a metadata policy check, not a determination
of legal compliance or verification of package license files.

Set audit_dependencies_on_change to true in .ai-pilled.json to enable npm auditing
from the post-tool hook. It compares dependency-file contents, checks the first observed
snapshot, and reuses complete results for unchanged inputs for up to one hour. Failures
remain blocking; incomplete results retry. Automatic calls have a 30-second process
limit and run only after the credential scan passes. This requires active trusted Codex
hooks and contacts the configured npm registry; it does not intercept every system-wide
package installation.

Post-tool hooks match every supported local tool event, including MCP tools. Hosted
tools such as web search are outside Codex hook coverage. Existing installations with
the older shell/edit matcher must be uninstalled and reinstalled, then reviewed in /hooks.
See [official hook coverage](https://learn.chatgpt.com/docs/hooks).

Post-tool summaries include one sentence, a proceed/wait indicator, and a next step.
Structured exit codes and MCP error flags are recognized without retaining raw tool
output. Unstructured outcomes remain unknown and request review of the original result.
No unsupported PostToolBatch event is invented.

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

Codex installation merges project-local .codex/hooks.json entries. Configuration and
installation metadata must be regular files within 1 MB; an update that would exceed
that limit is rejected before writing either file. **Review and trust
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
| Codex post-tool | Scan credentials, summarize tool/check status, optionally audit changed npm inputs |
| Codex stop | Run configured tests; request one repair pass if they fail |
| Explicit review | Ask Codex to review the staged diff with a strict result schema |

Pre-push enforces the same conventional subject format and 72-character limit on every
outgoing commit, including commits created without local hooks. Already-published history
reachable from the known remote tip is excluded. Pre-push tests require a clean working
tree and the pushed commit checked out at HEAD.
A secret removed in a later outgoing commit is still caught. More than 2,000 outgoing
commits requires a smaller audited range. Files larger than 2 MB produce an incomplete
scan, not a clean bill of health. Commit messages, identities, extra headers, annotated
tags, and destination ref names are scanned too. Internal Git operations ignore replacement
objects so local replacement refs cannot hide the original staged or outgoing content.

Credential matching recognizes AWS access-key IDs and same-line, 40-character secret-key
assignments named AWS_SECRET_ACCESS_KEY, aws_secret_access_key, or SecretAccessKey.
It also recognizes GitHub, OpenAI, Slack, and private-key patterns. AWS field names
follow the [credential settings reference](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html);
the secret-key length follows the [AWS access-key description](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/MakingRequests.html).
Credential matching is a limited deterministic check, not a complete security audit.
Use scan --patterns to also inspect Python ASTs for dynamic execution, unsafe object/YAML
parsing, shell=True, and complete environment dumps. Strict quality/Git/lifecycle checks
include these patterns automatically. At push time, AST checks inspect pushed tips;
credential checks still inspect every outgoing commit. Import aliases are recognized; comments and strings
are not treated as calls. MD5/SHA-1 uses are review notices unless explicitly marked
usedforsecurity=False. These conservative patterns do not model full data flow or alias
shadowing and are not proof of exploitability. Unparseable Python is incomplete.
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

Use prepare-release with the same --current/--since arguments to run local PR
readiness and write VERSION plus a new CHANGELOG.md section. The existing VERSION,
when present, must match --current. Failed checks, dirty/protected branches, version
mismatches, and duplicate changelog sections prevent preparation. Handwritten history
is preserved; an ordinary second-file write failure restores the first file. Review
and commit the resulting changes yourself. This command does not stage files, tag,
push, or publish, and it does not update package-manager version manifests.

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
latest 100 retained runs. It escapes findings and loads no external scripts or assets.
Local history is capped at 2 MB. Rotation retains whole recent records that fit;
a single oversized record is rejected before changing existing history. Oversized
legacy history must be archived before reading, or is bounded on the next recorded check.

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

Quality profile: **strict**. Configured commands: benchmark, coverage, deadcode, lint, repair, simplify, test, typecheck.
Configuration is not proof that checks passed; use quality to run them.

~~~text
usage: ai-pilled [-h] [--repo REPO]
                 {scan,check,review,review-checks,dependency-audit,python-audit,python-health,python-licenses,coverage,bundle,benchmark,dependency-health,licenses,release-plan,prepare-release,publish-release,update-readme,nightly-refactor,refactor,auto-merge,heal,full-audit,quality,ready,notify,summary,dashboard,lifecycle,install-codex-hooks,uninstall-codex-hooks,install-git-hooks,uninstall-git-hooks,hook} ...

positional arguments:
  {scan,check,review,review-checks,dependency-audit,python-audit,python-health,python-licenses,coverage,bundle,benchmark,dependency-health,licenses,release-plan,prepare-release,publish-release,update-readme,nightly-refactor,refactor,auto-merge,heal,full-audit,quality,ready,notify,summary,dashboard,lifecycle,install-codex-hooks,uninstall-codex-hooks,install-git-hooks,uninstall-git-hooks,hook}
    scan                Scan the Git index or working tree for credentials
    check               Run a configured quality command
    review              Review the staged snapshot with Codex
    review-checks       Run strict quality checks on the exact staged snapshot
    dependency-audit    Audit npm lockfile vulnerabilities
    python-audit        Audit fully pinned Python requirements without installing
                        packages
    python-health       Check a selected Python environment; query outdated versions
                        only with --outdated
    python-licenses     Match installed Python license metadata against an explicit
                        allowlist
    coverage            Check line coverage from coverage.py JSON
    bundle              Check built artifacts against a byte budget
    benchmark           Compare median process time against a local baseline
    dependency-health   Check installed npm tree and available versions
    licenses            Match lockfile licenses against an explicit allowlist
    release-plan        Generate changelog and semantic-version proposal
    prepare-release     Validate readiness and write VERSION/CHANGELOG.md
    publish-release     Verify an existing release tag; publish only with --publish
    update-readme       Refresh a generated README command reference
    nightly-refactor    Run a due daily refactor or watch explicitly in the foreground
    refactor            Run configured refactor steps in a disposable clone and export a
                        patch
    auto-merge          Inspect a pinned GitHub PR; enable only with --enable
    heal                Verify reversal of a failing HEAD; preview unless --apply
    full-audit          Run quality gates and optional isolated model perspectives
    quality             Run the configured quality profile
    ready               Validate a clean proposal branch and its quality checks
    notify              Preview or explicitly send a historical check digest
    summary             Summarize recorded checks and next steps
    dashboard           Build an offline check-history dashboard

options:
  -h, --help            show this help message and exit
  --repo REPO
~~~
<!-- ai-pilled:commands:end -->
