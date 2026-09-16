# Feature evidence and activation status

The approved requirements are in [FEATURES.md](FEATURES.md). This document separates
implemented commands from active automation and live-provider verification. See
[README.md](../README.md) for configuration and opt-in flags.

## Core workflows

| Requirement | Implementation | Evidence and limits |
| --- | --- | --- |
| Security after edits | Worktree/index credential scans; strict Python AST checks; PostToolUse handler | Real Git fixtures cover partial staging, encoded secrets, webhook credentials, formatted environment dumps, unsafe parsing, and shell execution. Python patterns are conservative signals, not a general vulnerability proof. Hook configuration must be trusted and active. |
| Review every commit | Conventional message and staged security Git hooks; optional Codex review | Real blocking Git hooks and fake provider failures tested. Installed Codex CLI caught a seeded defect in a live smoke test. Model review is opt-in; disabled by default. |
| Validate every push | Destination protection, outgoing-history scans, required tests, snapshot verification | Active Git pre-push hook in development; disposable local remotes verify successful updates and unchanged refs after protected-branch or failing-test blocks. Other fixtures cover historical credentials, changed snapshots, and missing evidence. Local hooks can be bypassed by users; server protections remain separate. |
| Dependency audit | npm vulnerability, installed-tree health, outdated versions, exact license-expression policy; opt-in post-tool change audits | Real npm fixtures and malformed/offline response tests. npm only; license metadata matching is not legal analysis. Cache reuse is bounded and preserves failures. |
| Tool-chain summary | Structured PostToolUse summaries and historical summary command | Exit codes and MCP errors tested without retaining raw output. Unknown outcomes remain unknown. No unsupported batch event is claimed. |

## Automation backlog

| # | Requirement | Available behavior and remaining limits |
| --- | --- | --- |
| 1 | Dead code detector | Configured deadcode command; this repo runs Vulture. |
| 2 | Type safety verifier | Configured typecheck command; this repo runs mypy. |
| 3 | Dependency health | dependency-health validates npm's installed tree and queries newer versions. |
| 4 | Commit message validator | commit-msg hook enforces conventional subjects and scans credentials. |
| 5 | Branch protector | pre-push matches configured protected destination patterns. |
| 6 | Test coverage auditor | Fresh coverage.py JSON counts and explicit percentage budget. |
| 7 | Performance regression detector | Repeated process timings, median baseline, explicit baseline replacement, host/command matching. |
| 8 | Bundle size watcher | Built artifact byte budgets; rejects links and missing/oversized inputs. |
| 9 | Changelog generator | release-plan derives escaped notes from a bounded explicit commit range. |
| 10 | README updater | One generated command-reference block; preserves handwritten content and checks drift. |
| 11 | Parallel full audit | full-audit runs quality first; explicit --model-reviews enables isolated perspectives, one to three workers. Concurrency tested with fake reviewers. |
| 12 | PR-ready checker | ready requires a clean committed proposal on a non-protected branch and passing quality gates. |
| 13 | Release flow | prepare-release writes verified metadata; publish-release validates committed metadata and existing local/remote tags, previews by default. Explicit publication tested with fake GitHub responses only. |
| 14 | Simplify → fix → test | refactor runs trusted simplify/repair commands in a disposable clone, validates policy and quality, then exports a patch. No automatic source edits. |
| 15 | Slack notifications | notify slack previews; --send uses an explicitly configured webhook. Fake transport tests only. |
| 16 | Linear tickets | notify linear previews; --send creates an issue in an explicit team. Fake transport tests only. |
| 17 | GitHub comments | notify github previews; --send comments on an explicit issue/PR. Fake transport tests only. |
| 18 | Email digest | notify email previews; --send submits via authenticated SMTP over TLS to an explicit address. Fake transport tests only. |
| 19 | Metrics dashboard | Offline history, result counts, measurements, and findings; HTML escaping tested. Visual browser rendering has not been verified. |
| 20 | Semantic release | Conventional commits determine stable major/minor/patch proposals; breaking changes win. Prerelease versioning and package-registry publication are not implemented. |
| 21 | Trunk auto-merge | Explicit PR, base, and head selection; approved/mergeable/required-check gates; preview default, --enable may merge immediately. Fake GitHub CLI tests only. |
| 22 | AI bug bounty | Full audit provides local correctness/security findings with source locations. No external bounty submission, rewards system, or live multi-reviewer run. |
| 23 | Nightly refactoring | nightly-refactor provides timezone-aware daily checks, persisted attempt deduplication, serialized execution, and optional foreground --watch. DST/restart/failure behavior is tested with controlled clocks. No recurring process is installed or active. |
| 24 | Self-healing | heal verifies a passing single-commit reversal in a disposable clone and requires the original test failure to reproduce afterward. Preview default; explicit --apply makes a normal local revert commit. Real Git mutation tests use disposable repositories only. |

## Verification and operation

The local strict profile runs credential/Python checks, unit and integration tests,
Ruff, mypy, Vulture, and fresh coverage with an 80% minimum. The minimum Python 3.10
runtime has been exercised alongside Python 3.14. Results apply to the tested snapshot;
historical summaries do not certify later changes.

There is no active remote CI run claimed here. Provider failures, unavailable executables,
timeouts, invalid results, and changed snapshots block dependent actions. A completed
check failure differs from an incomplete check that could not finish. Model findings
still need engineering review.

Installing Codex hook files is separate from trusting/activating them in Codex. Review
/hooks in the target project. Notification delivery, auto-merge, release publication,
and self-healing application require their explicit command flags. No recipients,
schedules, package publication, or server branch protections are inferred from setup.
