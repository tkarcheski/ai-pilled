# Feature status and evidence

Updated 2026-09-16. The source of feature intent is [FEATURES.md](FEATURES.md),
not claims made by the original scaffold. This report distinguishes implemented
behavior, reproducible tests, actual activation, and work still needed.

The verification baseline is `5844cd2`: 466 tests and seven configured quality gates
passed through the active Python 3.14 staged review. Prepared CI snapshot `f04f5de`
passed the same quality profile and all four E2E scenarios on Python 3.10. An actual full-audit of `5844cd2` also passed all seven gates with zero
model workers. Comprehensive
staged review and Python dependency auditing are enabled in this repository.
GitHub workflow publication is blocked by the current login's missing `workflow`
scope. GitLab pipelines are **planned and deferred at the user's request**.

Python-literal credential inspection adds mandatory parsing to secret scans. Dogfooding
caught a performance-budget failure: 0.272 seconds median versus the unchanged
0.166-second baseline (64.1% increase; 20% budget). Profiling attributes the extra
work to parsing/traversing Python source. Security coverage is retained; performance
acceptance remains open, and the saved baseline has not been raised.

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
Git blobs. ASCII token boundaries prevent non-ASCII neighboring bytes or text from
hiding recognizable credentials in scans or redacted output. Quoted JSON strings are decoded once for Unicode/slash escapes, including
values hidden by duplicate keys; malformed literals do not suppress raw scanning.
AWS secret-key field names are paired with their decoded JSON values, including
escaped keys and duplicate entries. The shared redactor handles nested dictionary fields
and masks those values while retaining JSON keys/quoting and unrelated data. Complete
private-key block redaction still precedes individual quoted-string handling.
This is direct string-escape handling, not arbitrary encoding or runtime data-flow analysis.
PyPI publishing tokens follow the provider’s documented prefix and minimum
payload length; the shared pattern also redacts reports/history and blocks credential-like
package identities before registry queries. Python string/byte constants are parsed without
execution, including adjacent literals and Python escapes; findings cite the start of
the source literal. Parser warnings are suppressed because Python can echo an
unredacted source line; syntax failures still yield incomplete evidence. Runtime string
computations and arbitrary encodings are not evaluated. History caches separate
Python interpretation from identical non-Python blobs. Strict Python AST checks flag environment dumps, unsafe parsing, shell
execution (including implicit shell APIs and literal truthy shell flags), unsafe YAML
single/multiple-document loaders, weak cryptographic patterns, and explicit TLS-verification bypasses in
Requests/HTTPX APIs or the unverified SSL context factory, including import aliases.
Requests also rejects literal zero/empty verification values, which disable certificates;
`None` retains Requests defaults and remains allowed.
Import lookup separates module, function, class, lambda, and comprehension bodies, including aliases
in defaults and enclosing closures. Comprehension bodies skip class imports, their first
iterable uses the containing scope, and loop targets remain local, following the
[Python scope rules](https://docs.python.org/3/reference/expressions.html#displays-for-lists-sets-and-dictionaries).
Unrelated nested imports cannot hide outer calls;
relative imports are not treated as public packages. Shell rules include `os.popen`,
`subprocess.getoutput/getstatusoutput`, and `asyncio.create_subprocess_shell`; YAML
rules include `unsafe_load`, `unsafe_load_all`, and `load_all` without an explicit safe loader.
Environment-dump checks include literal string formatting, serialization keyword arguments,
and environment value/item views, including starred arguments and byte environments.
Credential-named literal lookups through `environ`, `environb`, `getenv`, and `getenvb`
are blocked at logging calls. Names ending in TOKEN, SECRET, PASSWORD, API_KEY, or
PRIVATE_KEY, plus AWS access/secret key names, are review signals; ordinary HOME/PATH
and metadata names remain allowed. Lookup fallbacks, conditional result branches,
boolean results, and assignment expressions are inspected; condition-only credential
checks do not expose their value. This does not trace separate assignments or arbitrary data flow.
Argument-array subprocess APIs and explicit safe YAML loaders remain allowed. Referenced conflicting imports
in one scope are incomplete. Verified defaults/custom CA bundles remain allowed.
General assignment/rebinding, global/nonlocal mutation, and session-instance data flow
are not modeled; these patterns do not certify runtime behavior.
Shared JSON input parsing rejects duplicate object keys (including escaped aliases)
and nonfinite numbers, so later fields cannot erase earlier findings or safety settings.
Parser errors do not echo keys or provider payloads. Deep expression traversal is iterative. Scanning is bounded and reports unreadable,
oversized, unresolved, and unsupported content as incomplete.

**Evidence:** `test_security.py`, `test_python_security.py`, `test_redaction.py`,
`test_json_data.py`, and `test_report_bounds.py`; actual credential-blocked commits
are also covered by `test_e2e.py`. Reports redact findings rather than echo secret
values. Runtime Git reads disable replacement objects and legacy graft overlays so local
metadata cannot substitute content or conceal outgoing ancestry. Git filesystem paths
preserve trailing whitespace and undecodable filename bytes; repository discovery never
trims a selected checkout into a different sibling. `test_git_paths.py` covers both scan
scopes, comprehensive review, quality, and a real credential-blocked hook commit. Both default and
environment-selected graft bypasses have credential-history regression tests. Hook
installation configuration reads use the bounded command runner (16 KB per value),
preserve exact trailing newlines, and distinguish absent keys from command failures.
New Git hooks and manifests use exclusive descriptor creation; concurrent files or
symlinks cannot be truncated. The creation plan retains preflight absence, so a later
file cannot be silently adopted; all hook contents/executable permissions are rechecked
before activation. Rollback removes only matching inodes created by that
attempt and preserves detected replacements. If configuration activation succeeded
or its outcome cannot be read after a command failure, ready hooks and the ownership
manifest are retained for inspection/retry instead of deleting potentially active gates. These cooperative installation protections
do not claim isolation from every hostile parent-directory race.
Commit-message, installation-manifest, and owned-hook reads require bounded regular
files (64 KB); rejected special/oversized files leave hooks and Git configuration intact.

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
disabled hooks, a restricted environment, and validated structured source locations. Model output and cited source use bounded
regular-file reads without following final symlinks.
`review --comprehensive` requires deterministic evidence and model findings to refer
to the same index.

**Evidence:** `test_staged_review.py`, `test_git_hooks.py`, `test_codex_review.py`,
and the partial-staging E2E case. The new reviewer passed its own staged implementation.
A real installed Codex CLI caught a seeded defect in an earlier smoke test. Current
multi-reviewer behavior has fixture coverage only; no new model workers were started.
Full audits pin HEAD across quality and review, reject assume-unchanged/skip-worktree
flags before model use, and recheck actual source afterward; hidden or committed
replacements cannot combine old quality evidence with a different reviewed snapshot.

**Limits:** configured commands and interpreters are trusted code. A disposable copy
is not an operating-system sandbox. Model review is disabled by default and is not
currently enabled on every local commit. Model output requires engineering judgment.

### 3. Validate every push — active locally

**Entry point:** installed pre-push hook; source
[pre_push.py](../ai_pilled/pre_push.py). It checks the actual destination refs,
protected branch patterns, all selected outgoing commit subjects and credential
history, tip security patterns, configured tests, and a stable clean snapshot.
Raw commit headers, author identities, tag chains, and destination names are scanned.
Non-deletion pushes reject assume-unchanged/skip-worktree flags, including hidden policy
changes. Before/after test scans compare actual source, permissions, index, and HEAD;
a hidden local fix or hidden test mutation cannot certify a different pushed commit.
New refs exclude ancestry only after verifying advertisements from the actual destination;
forged local tracking refs cannot hide unpublished commits. Tips retain security scans.
Traversal parents must match raw outgoing commit parents: unverified shallow boundaries
are incomplete, while verified published boundaries can delimit a complete new range.
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
| npm vulnerability audit | Lockfile-only audit, scripts disabled, validated package/count evidence and matching exit status at the requested low threshold | `test_dependencies.py`; npm fixtures and malformed/offline responses. No package install or automatic fix. Requires supported npm audit JSON. |
| npm health and licenses | Installed-tree consistency, available updates, matching process/JSON evidence, explicit license allowlist | `test_dependency_health.py`; missing/unknown evidence remains blocking. No legal compliance conclusion. |
| Python vulnerabilities | `python-audit`, exact listed pins, `pip-audit --no-deps --disable-pip --strict` | `test_python_dependencies.py`; all selected packages must appear exactly once with the expected version; process exit status must agree with vulnerability evidence. No install, build, resolver, or fix execution. |
| Python environment health | `python-health --python PATH`; `pip inspect` plus `pip check` | `test_python_health.py`; isolated interpreter prevents repository `pip.py` shadowing. Environment fingerprint must remain stable. Interpreter/startup environment must be trusted. |
| Python updates | Optional `python-health --outdated`, confirmed per-package PyPI queries | Failed/unknown lookups remain incomplete. A reproduced `pip list --outdated` empty-success case motivated explicit index queries. Private/unpublished versions require manual comparison. |
| Python licenses | `python-licenses --python PATH --allow EXPRESSION` | Exact declared expression matching. Missing, unknown, or prose-only metadata remains incomplete. No inferred SPDX evaluation or legal analysis. |
| Automatic auditing | `python_requirements` and `python_audit_executable` in quality; `audit_dependencies_on_change` in PostToolUse | Enabled here for `requirements-dev.txt` and `requirements-audit.txt` (36 distinct pins). Quality obtains fresh results; lifecycle may reuse complete matching evidence for at most one hour. Failures stay blocking; incomplete checks are retried with a 30-second provider limit. Cached identity, integer counts, selected Python package coverage, finding shape, truncation, and status must agree. Contradictory entries or older evidence are refreshed. |

**Live dogfood evidence:** both development (ten packages) and audit-tool (28 packages)
locks install from hash-verified wheels in fresh Python 3.10 and 3.14 environments,
with `pip check` passing. Each freshly installed auditor checked the combined 36 distinct
pins with zero advisories. The development lock explicitly includes the previously
missing Python 3.10 `tomli` dependency. A separate, never-installed `requests==2.19.1`
fixture produced ten advisories and failed as expected. Earlier environment health
checks confirmed package consistency and PyPI update evidence; these are distinct
from the current lock audit. Manual PostToolUse reused matching fresh audit evidence.

**Scope limits:** only explicitly listed exact pins are audited. Transitive closure is
not inferred. Ranges, markers, extras, URLs, recursive includes, editable installs,
and unsupported options are rejected. Exact-pin exports with repeated SHA256 hashes
and bounded continuations are supported; hashes are syntax-checked and fingerprinted,
not downloaded or verified against artifact bytes. Joined credential and changed-hash
regressions block provider calls or stale evidence.
The auditor runs in a separate environment, with its dependency lock included in
the selected audit scope. Python, pip, and ensurepip bootstrap packages remain outside
these locks. Python health needs pip inspect schema 1; update queries additionally
need pip's JSON index output. Health/license execution requires an explicit interpreter.

### 5. Tool-chain summaries — implemented, lifecycle activation unverified

**Entry points:** PostToolUse, `summary`, `dashboard`; sources
[lifecycle.py](../ai_pilled/lifecycle.py) and [reporting.py](../ai_pilled/reporting.py).
Summaries include a sentence, blocker state, warnings, and next action. Structured
exit codes and MCP errors determine tool success; running and unknown outcomes are
preserved. Stop-hook recursion metadata must be a real boolean; strings such as
`"false"` cannot suppress a blocking result and are rejected before configured tests run.
Summaries, dashboard counts, and suggestions share bounded traversal of
nested check/step results; a newer child result supersedes older evidence for that check.
A passing parent cannot hide a failed child. Raw tool transcripts are not retained in the summary/history.

**Evidence:** `test_lifecycle.py`, `test_reporting.py`, and real CLI E2E checks.
The dashboard escapes content, uses a restrictive content policy, and writes private
output atomically. Symlinks/special files cannot redirect dashboard writes.

**Limits:** no unsupported batch-completion event is claimed. Historical success does
not certify later changes. Browser rendering has not been verified. The `suggest` command prioritizes recorded failures and missing feature configuration,
provides explicit check argument lists, and labels historical evidence. It is read-only;
external actions are never replayed automatically. Nested newer check results supersede
older child results; priority, bounds, redaction, and no-execution tests are in
`test_suggestions.py`.

The existing scan benchmark at `ac70b2a` passed its unchanged 20% budget: three-run
median 0.16828 seconds versus baseline 0.16558 seconds (1.63% increase). This measures
that local run, not a latency guarantee for future snapshots or larger repositories.

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
| 9 | Changelog — implemented | `release-plan`, bounded explicit conventional-commit range with raw ancestry verification (truncated shallow history is incomplete); `test_releases.py` | Inspect generated notes; no automatic publication. |
| 10 | README updater — used here | Generated CLI block with drift check; `test_documentation.py` | Handwritten prose is preserved; documentation correctness is not inferred. |
| 11 | Full audit / parallel review — opt-in | Comprehensive quality first regardless of profile, optional one-to-three isolated perspectives; `test_full_audit.py` | Concurrency tested with fake reviewers; no live parallel run claimed. |
| 12 | PR-ready checker — implemented | `ready`: clean committed non-protected proposal plus passing quality; `test_pipeline.py` | Does not create a PR or assert hosted checks passed. |
| 13 | Release flow — opt-in | `prepare-release`, `publish-release`, exact local/remote tags and bounded regular-file metadata reads; release/publishing tests | Preview default. Actual GitHub publication tested with provider fixtures only. |
| 14 | Simplify → fix → test — implemented | `refactor`, trusted commands in disposable clone, verified patch export; `test_refactor.py` | Candidate scans/checks isolate inherited Git routing; generated credentials are blocked. No automatic patch application; clone is not an OS sandbox. |
| 15 | Slack notifications — opt-in | Preview and explicit `notify slack --send`; `test_notifications.py` | Fixture transport only; no live delivery or recipient configured. |
| 16 | Linear tickets — opt-in | Preview and explicit team/`--send`; notification tests | Fixture transport only; no live issue created. |
| 17 | GitHub comments — opt-in | Explicit repository and issue/PR with `--send`; notification tests | Fixture transport only; no live comment posted. |
| 18 | Email digest — opt-in | Minimal digest, explicit addresses, authenticated SMTP over TLS; notification tests | Fixture transport only; no live email sent. |
| 19 | Metrics dashboard — implemented | Offline escaped HTML and bounded private history; reporting tests, CLI E2E | Browser appearance unverified; records are historical. |
| 20 | Semantic release — partial | Stable major/minor/patch proposals from conventional commits; release tests | Prerelease policy and package-registry publishing not implemented. |
| 21 | Trunk auto-merge — opt-in | Explicit PR/base/head, approvals/mergeability/check gates, matching process/check evidence, head revalidation; `test_merging.py` | Preview default; `--enable` can merge immediately. Only fake GitHub responses tested. |
| 22 | AI bug bounty — partial | Local correctness/security findings through review/full-audit | No external bounty submission, reward workflow, or live multi-reviewer campaign. |
| 23 | Nightly refactoring — implemented, inactive | Timezone-aware daily attempts, locks, persisted deduplication, foreground watch; `test_scheduling.py` | Controlled-clock DST/restart/failure tests. No recurring process installed. |
| 24 | Self-healing — opt-in | `heal`: verify one-commit reversal, full quality, reproduce original failure again; `test_healing.py` | Preview default; explicit apply creates a normal local revert. Real mutations tested only in disposable fixtures; no automatic production rollback. |

## CI and end-to-end evidence

`python scripts/run_e2e.py` runs four multi-step scenarios through the real CLI:

1. Install hooks, commit, push to a local bare remote, consume lifecycle events,
   summarize results, and generate the offline dashboard.
2. Reject a bad subject, a staged credential, a TLS bypass hidden by an unstaged fix,
   implicit shell/unsafe YAML APIs hidden by unstaged fixes, and a failing test hidden by partial staging;
   confirm HEAD does not move.
3. Reject hidden worktree changes, a protected destination, and a failing-test push; confirm remote refs do not move.
4. Run Python audit/lifecycle through a fixture provider; preserve vulnerability and
   incomplete statuses, including cache behavior.

All four passed on Python 3.10 and 3.14. The runner produces private
`.ai-pilled/e2e.json` and `.ai-pilled/e2e.xml` with every test outcome. Exported artifacts
contain named outcomes rather than raw process transcripts. The E2E repository uses
small configured lint/type/deadcode/coverage fixture commands; the actual development
quality run separately exercises Ruff, mypy, Vulture, and fresh coverage.

| Pipeline | Status | Evidence / blocker |
| --- | --- | --- |
| Local quality and staged review | Active | Seven gates: security, tests, Ruff (syntax/imports plus bugbear and Bandit), mypy, Vulture, fresh coverage, live Python dependency audit. Missing tools/registry evidence block. |
| Local shared E2E | Verified on 3.10 and 3.14 | Real Git/CLI workflows; registry response fixtures explicitly distinguished from live audit evidence. |
| GitHub Actions | Prepared and locally validated at `f04f5de`; publication blocked | Current 3.10 seven-gate/E2E evidence, 92.50% coverage, hash-enforced development and auditor bootstraps, immutable action pins, and explicit artifacts are documented in [CI.md](CI.md). GitHub rejected publication after pre-push passed because the login lacks workflow scope. No hosted run or required-check activation is claimed. |
| GitLab CI | Planned / user-deferred | No project selected, pipeline activated, or remote run claimed. |

Readiness, release publication, refactor, and healing also reject hidden index flags
when a clean committed checkout is required. Fixtures verify that hidden local fixes
or metadata cannot certify a different commit, export a misleading patch, or trigger
provider calls; rejected operations preserve the local edits. Refactor also checks its
disposable candidate after each editing step and after quality: a command cannot hide
the tested fix with index flags and export an empty or incomplete patch.

Refactor and healing policy comparisons use bounded regular-file reads; generated
FIFO, symlink, and oversized policies produce incomplete results without exporting
a patch or changing the source checkout. The real repository refactor preview at
`7e2b611` passed simplify, repair, and all seven quality gates with zero patch bytes,
using the candidate index guards; the source checkout remained clean.

Scheduler state and lock files must be regular files opened without following symlinks.
Records are read through a 16 KB bound; FIFO, symlink, and oversized-state regressions
return incomplete without running refactor or replacing the original file.

Coverage reports, streamed bundle files, performance baselines, and README inputs
also validate the opened descriptor as a regular file. Coverage/README replacement
symlinks are rejected; no external content is accepted as local evidence or copied
into generated documentation. These checks retain their explicit read-size limits.

History reads and writes reject multiply linked files. Appending cannot alter another
file through a hard link, and successful writes enforce mode 0600 on the validated
history descriptor. Rejected links retain their contents and permissions.

History readers/writers, hook installers, and performance baselines wait at most two
seconds for cooperative locks. Busy locks return an explicit unavailable result;
contention never deletes a lock, appends partial history, runs a benchmark, or enters
an installer mutation section. The scheduler already reports busy without waiting.

## Known gaps and prioritized follow-ups

| Priority | Follow-up | Why / completion evidence |
| --- | --- | --- |
| P1 | Reduce Python-literal scan overhead | Actual dogfooding exceeds the unchanged performance budget; retain decoded-literal security coverage and require measured improvement. |
| P1 | Complete hosted GitHub acceptance when credentials permit | Workflow refresh and local parity are complete. Publishing remains blocked by OAuth scope. Inspect both matrix jobs and downloaded artifacts after publication; never substitute local evidence for a hosted result. |
| Done / monitor | Isolate watch fixture interruption | A captured failure identified a shared `time.sleep` patch that could interrupt Git subprocess cleanup before the watch report. A deterministic delayed-command probe reproduced it; the fixture now replaces only the scheduling module’s time reference. Older failures without named diagnostics cannot be attributed conclusively. Keep redacted failure capture active. |
| Done | Isolate disposable operations from inherited Git routing | Reproduced a refactor credential-export bypass and healing candidate misrouting. Candidate scans/quality now isolate routing; real fixtures verify rejection and preservation of original HEAD/index/worktree. Model review already strips Git variables from its subprocess environment. |
| Done | Product-generated follow-up suggestions | `suggest` prioritizes recorded failures and missing configuration, labels historical evidence, and gives explicit next check commands. It performs no checks or external actions; nine targeted tests cover ordering, nested evidence, redaction, and safe integration follow-ups. |
| Done | Support SHA256 requirement exports | Exact pins with repeated hashes and bounded continuations; malformed syntax, split credentials, and changed hashes are covered. No setup code runs. Other lock formats and conditional dependency resolution remain outside scope. |
| Done | Hash-pin and audit the auditor’s dependencies | Separate 28-package lock, fresh hash-enforced wheel installs on 3.10/3.14, and zero advisories across 36 distinct combined pins. Interpreter/pip/ensurepip bootstrap remains outside the lock. |
| P2 | Verify live Codex lifecycle and dashboard appearance | Demonstrate actual events and visual output in the allowed environment; installed files/unit tests are insufficient activation evidence. |
| P3 | Hosted provider acceptance | Explicit target and authorization before real notifications, release publication, merging, or rollback; capture provider IDs/results once exercised. |
| Deferred | GitLab, prerelease policy, package publishing, external bounty workflow | Keep planned until their scope and target are selected; do not present fixture coverage as live completion. |

Changes are delivered as small commits with active checks and frequent pushes.
No recurring jobs, notification deliveries, hosted merges/releases, or new agent
workers have been activated as a side effect of this development work.
