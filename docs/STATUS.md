# Feature status and evidence

Updated 2026-09-16. The source of feature intent is [FEATURES.md](FEATURES.md),
not claims made by the original scaffold. This report distinguishes implemented
behavior, reproducible tests, actual activation, and work still needed.

The verification baseline is `74ef957`: 336 discovered tests, a shared
four-scenario end-to-end runner, and seven configured quality gates. Comprehensive
staged review and Python dependency auditing are enabled in this repository.
GitHub workflow publication is blocked by the current login's missing `workflow`
scope. GitLab pipelines are **planned and deferred at the user's request**.

## What the statuses mean

- **Implemented / tested:** code exists and named tests exercise it. Provider fixtures
  verify integration contracts; they do not prove delivery to a live service.
- **Active here:** the repository configuration or Git hooks actually invokes it.
- **Opt-in:** an explicit configuration option or command flag is required.
- **Blocked:** implementation or activation depends on an unavailable prerequisite.
- **Planned:** acceptance work remains; this is not a claim of a shipped integration.

Checks return `pass`, `fail`, or `incomplete`, with CLI exit codes 0, 1, and 2.
Unavailable tools, timeouts, malformed provider output, missing evidence, and changed
snapshots cannot be represented as a successful check. Configuration/protocol errors
also exit 2. Historical summaries describe recorded evidence, not the current files.

## Core requirements

### 1. Security after file edits — implemented, hook activation unverified

**Entry points:** `scan --scope staged`, `scan --scope worktree --patterns`, and
`lifecycle` PostToolUse. Sources: [security.py](../ai_pilled/security.py),
[python_security.py](../ai_pilled/python_security.py), and
[lifecycle.py](../ai_pilled/lifecycle.py).

Credential scanning covers file contents, names, UTF-16/32 BOM encodings, and staged
Git blobs. Strict Python AST checks flag environment dumps, unsafe parsing, shell
execution, and weak cryptographic patterns, including supported import aliases.
Deep expression traversal is iterative. Scanning is bounded and reports unreadable,
oversized, unresolved, and unsupported content as incomplete.

**Evidence:** `test_security.py`, `test_python_security.py`, `test_redaction.py`,
`test_json_data.py`, and `test_report_bounds.py`; actual credential-blocked commits
are also covered by `test_e2e.py`. Reports redact findings rather than echo secret
values. Runtime Git reads disable replacement objects so substituted local objects
cannot hide the original content being checked.

**Activation / limits:** Git commit/push scanning is active here. Codex hook files
are installed, but live trust/activation has not been verified. A manual lifecycle
smoke test passed. AST checks are conservative Python patterns, not whole-program
analysis; other languages currently receive credential checks. An after-tool hook
can report a problem but cannot undo an already completed edit or external action.

**Remaining acceptance:** verify actual Codex lifecycle delivery in a trusted project;
add language-specific analysis only with appropriate fixtures and clear guarantees.

### 2. Review every commit — active deterministic checks, opt-in model review

**Entry points:** Git pre-commit/commit-msg, `review-checks`, and
`review --comprehensive`. Sources: [staged_review.py](../ai_pilled/staged_review.py),
[codex_review.py](../ai_pilled/codex_review.py), and
[git_hooks.py](../ai_pilled/git_hooks.py).

`review_checks_on_commit: true` is enabled here. Every new commit runs strict checks
against a disposable copy of the exact index: credentials/Python patterns, tests,
lint, type checking, dead code, coverage, and configured Python dependency audit.
Missing commands block completion even if the repository profile is lazy. Staged
configuration and staged source are authoritative. Unstaged fixes cannot hide broken
staged code. Source executables come from that copy; reusable local tools must be
ignored and untracked. Executables deleted from HEAD cannot be borrowed from leftovers
in the working tree. Changed source, permissions, index, or HEAD invalidate evidence.

The commit-msg hook checks conventional subjects, length, and credentials. Optional
model review checks message alignment and concrete correctness/security defects. It
uses the existing Codex subscription login, a bounded staged snapshot, read-only mode,
disabled hooks, a restricted environment, and validated structured source locations.
`review --comprehensive` requires deterministic evidence and model findings to refer
to the same index.

**Evidence:** `test_staged_review.py`, `test_git_hooks.py`, `test_codex_review.py`,
and the partial-staging E2E case. The new reviewer passed its own staged implementation.
A real installed Codex CLI caught a seeded defect in an earlier smoke test. Current
multi-reviewer behavior has fixture coverage only; no new model workers were started.

**Limits:** configured commands and interpreters are trusted code. A disposable copy
is not an operating-system sandbox. Model review is disabled by default and is not
currently enabled on every local commit. Model output requires engineering judgment.

### 3. Validate every push — active locally

**Entry point:** installed pre-push hook; source
[pre_push.py](../ai_pilled/pre_push.py). It checks the actual destination refs,
protected branch patterns, all selected outgoing commit subjects and credential
history, tip security patterns, configured tests, and a stable clean snapshot.
Raw commit headers, author identities, tag chains, and destination names are scanned.
New refs exclude ancestry only after verifying advertisements from the actual destination;
forged local tracking refs cannot hide unpublished commits. Tips retain security scans.
History traversal, object caching, and tag depth have explicit bounds.

**Evidence:** `test_pre_push.py` plus actual local bare-remote E2E pushes. Protected
branch and failing-test rejections leave remote refs unchanged. Regression fixtures
cover historical secrets, replacement refs, malformed updates, and changed evidence.
Normal development pushes use the installed hook; it has not been bypassed.

**Limits / acceptance:** local hooks are user-bypassable. Server branch protection and
required hosted checks are separate controls and have not been configured or claimed.

### 4. Dependency auditing — npm and Python implemented; Python active here

| Capability | Available behavior | Evidence and remaining limits |
| --- | --- | --- |
| npm vulnerability audit | Lockfile-only audit, scripts disabled, validated package/count evidence | `test_dependencies.py`; npm fixtures and malformed/offline responses. No package install or automatic fix. Requires supported npm audit JSON. |
| npm health and licenses | Installed-tree consistency, available updates, explicit license allowlist | `test_dependency_health.py`; missing/unknown evidence remains blocking. No legal compliance conclusion. |
| Python vulnerabilities | `python-audit`, exact listed pins, `pip-audit --no-deps --disable-pip --strict` | `test_python_dependencies.py`; all selected packages must appear exactly once with the expected version. No install, build, resolver, or fix execution. |
| Python environment health | `python-health --python PATH`; `pip inspect` plus `pip check` | `test_python_health.py`; isolated interpreter prevents repository `pip.py` shadowing. Environment fingerprint must remain stable. Interpreter/startup environment must be trusted. |
| Python updates | Optional `python-health --outdated`, confirmed per-package PyPI queries | Failed/unknown lookups remain incomplete. A reproduced `pip list --outdated` empty-success case motivated explicit index queries. Private/unpublished versions require manual comparison. |
| Python licenses | `python-licenses --python PATH --allow EXPRESSION` | Exact declared expression matching. Missing, unknown, or prose-only metadata remains incomplete. No inferred SPDX evaluation or legal analysis. |
| Automatic auditing | `python_requirements` and `python_audit_executable` in quality; `audit_dependencies_on_change` in PostToolUse | Enabled here for `requirements-dev.txt`. Quality obtains fresh results; lifecycle may reuse complete matching evidence for at most one hour. Failures stay blocking; incomplete checks are retried with a 30-second provider limit. |

**Live dogfood evidence:** pip-audit 2.10.1 checked all nine development pins with zero
advisories. A separate, never-installed `requests==2.19.1` fixture produced ten
advisories and failed as expected. The development environment health check inspected
ten installed packages, confirmed ten PyPI version queries, and found no conflicts
or updates. Manual PostToolUse correctly reused the fresh matching audit.

**Scope limits:** only explicitly listed exact pins are audited. Transitive closure is
not inferred. Ranges, markers, extras, URLs, recursive includes, editable installs,
and hash-based exports are currently rejected; export a supported resolved pin list.
The standalone audit tool's own environment is separate from the selected development
requirements. Python health needs pip inspect schema 1; update queries additionally
need pip's JSON index output. Health/license execution requires an explicit interpreter.

### 5. Tool-chain summaries — implemented, lifecycle activation unverified

**Entry points:** PostToolUse, `summary`, `dashboard`; sources
[lifecycle.py](../ai_pilled/lifecycle.py) and [reporting.py](../ai_pilled/reporting.py).
Summaries include a sentence, blocker state, warnings, and next action. Structured
exit codes and MCP errors determine tool success; running and unknown outcomes are
preserved. Raw tool transcripts are not retained in the summary/history.

**Evidence:** `test_lifecycle.py`, `test_reporting.py`, and real CLI E2E checks.
The dashboard escapes content, uses a restrictive content policy, and writes private
output atomically. Symlinks/special files cannot redirect dashboard writes.

**Limits:** no unsupported batch-completion event is claimed. Historical success does
not certify later changes. Browser rendering has not been verified. Follow-up feature
suggestions beyond generic remediation are planned below.

## All 24 requested automations

| # | Feature and status | Implementation / verification | Remaining acceptance or limits |
| --- | --- | --- | --- |
| 1 | Dead code — active | `commands.deadcode`, Vulture; `test_pipeline.py` | Python configured here; other languages need their own trusted command. |
| 2 | Type safety — active | `commands.typecheck`, mypy with untyped-body checks; pipeline tests | This is not strict whole-project typing; third-party/stub coverage varies. |
| 3 | Dependency health — opt-in | npm `dependency-health`, Python `python-health`; both health test modules | Selected installed environment only; no automatic updates. |
| 4 | Commit messages — active | Shared conventional-subject checker, commit-msg and outgoing-history gates | Semantic message alignment requires optional model review. |
| 5 | Branch protection — active locally | Actual pre-push destination patterns; local remote E2E | Hosted branch protections remain unconfigured. |
| 6 | Coverage — active | Fresh coverage.py JSON and 80% line minimum; `test_metrics.py`, `scripts/check_coverage.py` | Line coverage is not branch coverage or a correctness proof. |
| 7 | Performance regression — opt-in | Repeated process timing, median baseline, host/command identity; `test_performance.py` | Explicit baseline replacement; machine-dependent measurements, not application profiling. Last recorded scanner comparison: about 122 ms vs 166 ms baseline. |
| 8 | Bundle size — opt-in | Existing artifact byte budgets; path/link/bounds tests in `test_metrics.py` | Does not build artifacts or infer a product-specific budget. |
| 9 | Changelog — implemented | `release-plan`, bounded explicit conventional-commit range; `test_releases.py` | Inspect generated notes; no automatic publication. |
| 10 | README updater — used here | Generated CLI block with drift check; `test_documentation.py` | Handwritten prose is preserved; documentation correctness is not inferred. |
| 11 | Full audit / parallel review — opt-in | Quality first, optional one-to-three isolated perspectives; `test_full_audit.py` | Concurrency tested with fake reviewers; no live parallel run claimed. |
| 12 | PR-ready checker — implemented | `ready`: clean committed non-protected proposal plus passing quality; `test_pipeline.py` | Does not create a PR or assert hosted checks passed. |
| 13 | Release flow — opt-in | `prepare-release`, `publish-release`, exact local/remote tags and committed metadata; release/publishing tests | Preview default. Actual GitHub publication tested with provider fixtures only. |
| 14 | Simplify → fix → test — implemented | `refactor`, trusted commands in disposable clone, verified patch export; `test_refactor.py` | Candidate scans/checks isolate inherited Git routing; generated credentials are blocked. No automatic patch application; clone is not an OS sandbox. |
| 15 | Slack notifications — opt-in | Preview and explicit `notify slack --send`; `test_notifications.py` | Fixture transport only; no live delivery or recipient configured. |
| 16 | Linear tickets — opt-in | Preview and explicit team/`--send`; notification tests | Fixture transport only; no live issue created. |
| 17 | GitHub comments — opt-in | Explicit repository and issue/PR with `--send`; notification tests | Fixture transport only; no live comment posted. |
| 18 | Email digest — opt-in | Minimal digest, explicit addresses, authenticated SMTP over TLS; notification tests | Fixture transport only; no live email sent. |
| 19 | Metrics dashboard — implemented | Offline escaped HTML and bounded private history; reporting tests, CLI E2E | Browser appearance unverified; records are historical. |
| 20 | Semantic release — partial | Stable major/minor/patch proposals from conventional commits; release tests | Prerelease policy and package-registry publishing not implemented. |
| 21 | Trunk auto-merge — opt-in | Explicit PR/base/head, approvals/mergeability/check gates, head revalidation; `test_merging.py` | Preview default; `--enable` can merge immediately. Only fake GitHub responses tested. |
| 22 | AI bug bounty — partial | Local correctness/security findings through review/full-audit | No external bounty submission, reward workflow, or live multi-reviewer campaign. |
| 23 | Nightly refactoring — implemented, inactive | Timezone-aware daily attempts, locks, persisted deduplication, foreground watch; `test_scheduling.py` | Controlled-clock DST/restart/failure tests. No recurring process installed. |
| 24 | Self-healing — opt-in | `heal`: verify one-commit reversal, full quality, reproduce original failure again; `test_healing.py` | Preview default; explicit apply creates a normal local revert. Real mutations tested only in disposable fixtures; no automatic production rollback. |

## CI and end-to-end evidence

`python scripts/run_e2e.py` runs four multi-step scenarios through the real CLI:

1. Install hooks, commit, push to a local bare remote, consume lifecycle events,
   summarize results, and generate the offline dashboard.
2. Reject a bad subject, a staged credential, and a defect hidden by an unstaged fix;
   confirm HEAD does not move.
3. Reject a protected destination and a failing-test push; confirm remote refs do not move.
4. Run Python audit/lifecycle through a fixture provider; preserve vulnerability and
   incomplete statuses, including cache behavior.

All four passed on Python 3.10 and 3.14. The runner produces private
`.ai-pilled/e2e.json` and `.ai-pilled/e2e.xml` with every test outcome. Exported artifacts
contain named outcomes rather than raw process transcripts. The E2E repository uses
small configured lint/type/deadcode/coverage fixture commands; the actual development
quality run separately exercises Ruff, mypy, Vulture, and fresh coverage.

| Pipeline | Status | Evidence / blocker |
| --- | --- | --- |
| Local quality and staged review | Active | Seven gates: security, tests, Ruff, mypy, Vulture, fresh coverage, live Python dependency audit. Missing tools/registry evidence block. |
| Local shared E2E | Verified on 3.10 and 3.14 | Real Git/CLI workflows; registry response fixtures explicitly distinguished from live audit evidence. |
| GitHub Actions | Prepared and locally validated at `915696c`; publication blocked | Both-runtime quality/E2E evidence, fresh3.10 environments, immutable action pins, and explicit artifacts are documented in [CI.md](CI.md). GitHub rejected publication after pre-push passed because the login lacks workflow scope. No hosted run or required-check activation is claimed. |
| GitLab CI | Planned / user-deferred | No project selected, pipeline activated, or remote run claimed. |

## Known gaps and prioritized follow-ups

| Priority | Follow-up | Why / completion evidence |
| --- | --- | --- |
| P1 | Complete hosted GitHub acceptance when credentials permit | Workflow refresh and local parity are complete. Publishing remains blocked by OAuth scope. Inspect both matrix jobs and downloaded artifacts after publication; never substitute local evidence for a hosted result. |
| P1 | Investigate intermittent full-suite failures if they recur | Earlier runs occasionally failed without named diagnostics; repeated exact reruns passed. Cause remains unknown. An ignored diagnostic wrapper retains redacted failed-test output; never bypass a gate or describe the issue as fixed. |
| Done | Isolate disposable operations from inherited Git routing | Reproduced a refactor credential-export bypass and healing candidate misrouting. Candidate scans/quality now isolate routing; real fixtures verify rejection and preservation of original HEAD/index/worktree. Model review already strips Git variables from its subprocess environment. |
| P2 | Product-generated follow-up suggestions | Prioritize current failed/incomplete checks and missing configuration, distinguish historical evidence, produce explicit next commands, and never activate external integrations automatically. |
| P2 | Broaden Python lock input support | Choose one well-defined export format, preserve exact-pin/coverage guarantees, and test markers/hashes/includes without evaluating package setup code. |
| P2 | Verify live Codex lifecycle and dashboard appearance | Demonstrate actual events and visual output in the allowed environment; installed files/unit tests are insufficient activation evidence. |
| P3 | Hosted provider acceptance | Explicit target and authorization before real notifications, release publication, merging, or rollback; capture provider IDs/results once exercised. |
| Deferred | GitLab, prerelease policy, package publishing, external bounty workflow | Keep planned until their scope and target are selected; do not present fixture coverage as live completion. |

Changes are delivered as small commits with active checks and frequent pushes.
No recurring jobs, notification deliveries, hosted merges/releases, or new agent
workers have been activated as a side effect of this development work.
