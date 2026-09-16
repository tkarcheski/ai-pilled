# Continuous integration and local parity

The GitHub workflow is prepared on the local `codex/ai-pilled-ci-pending` branch,
at `915696c`, including implementation baseline `74ef957`. Inspect its exact file:

```sh
git show codex/ai-pilled-ci-pending:.github/workflows/quality.yml
```

Publication was attempted with the normal pre-push hook enabled. Local validation
passed; GitHub rejected the OAuth login because it lacks `workflow` scope. There is
no hosted run or uploaded artifact to report. The separate visible Projects checkout
`ai-pilled-ci` contains the prepared branch and private local evidence. Normal feature
commits remain independently publishable on `codex/ai-pilled-implementation`.
GitLab pipelines remain planned and user-deferred.

## Workflow behavior

Both Python 3.10 and 3.14 jobs run on an ephemeral GitHub-hosted Ubuntu runner. Each
job has a 20-minute limit, read-only repository permissions, and checkout credential
persistence disabled. Concurrent runs for the same ref supersede older runs. Triggers
are push, pull request, and explicit workflow dispatch; no privileged pull-request-target
workflow or scheduled background job is configured.

The jobs create isolated development and pip-audit environments. Development tools
come from `requirements-dev.txt`; the separate audit tool is pinned to pip-audit 2.10.1.
Installation permits wheels only. Runtime ai-pilled remains standard-library based.
The audit tool's transitive installation dependencies are resolver-selected; this is
not a claim of a fully hash-locked CI toolchain. The current primary branch adds
a ten-package wheel hash lock verified in fresh Python 3.10 and 3.14 environments.
The prepared CI snapshot at `915696c` predates that lock; merge current source before
publication when credentials permit. The reproduction command below uses the current lock.

Each job runs the seven-gate quality profile and the shared real CLI/Git E2E scenarios.
An offline registry, missing tool, failed test, incomplete check, or malformed result
fails its step. E2E evidence collection still runs after another step fails, unless the
job was cancelled. That does not turn a failed job into a passing one.

The explicitly selected artifacts are:

- `.ai-pilled/quality.json`: structured overall and per-gate results.
- `.ai-pilled/coverage.json`: fresh coverage counts and source locations.
- `.ai-pilled/e2e.json`: E2E status, counts, and named failures.
- `.ai-pilled/e2e.xml`: every E2E outcome in JUnit format.

Artifacts are retained for seven days, named by Python version and commit SHA. Only
those four files are uploaded; source snapshots, tool environments, credentials,
message boards, and raw process transcripts are not included. Missing all evidence
fails artifact upload. A failed prerequisite may leave some individual files absent;
consult the failed steps instead of inferring success from the remaining artifacts.

Actions use immutable commits verified against their official release tags:

| Action | Release | Commit |
| --- | --- | --- |
| checkout | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| setup-python | v7.0.0 | `5fda3b95a4ea91299a34e894583c3862153e4b97` |
| upload-artifact | v7.0.1 | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` |

The workflow follows [GitHub's workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax)
and the official [artifact action inputs](https://github.com/actions/upload-artifact).
Local YAML parsing checked triggers, permissions, and the Python matrix. Hosted runner
semantics and artifact delivery still require an actual GitHub run after publication.

## Reproduce locally

Select the intended Python interpreter first. These commands mirror the workflow;
use an isolated checkout to compare runtimes without changing an existing tool environment.

```sh
export PYTHONDONTWRITEBYTECODE=1
python -m venv .ai-pilled/tools
.ai-pilled/tools/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements-dev.txt
python -m venv .ai-pilled/python-audit-tools
.ai-pilled/python-audit-tools/bin/python -m pip install --only-binary=:all: pip-audit==2.10.1
python -m ai_pilled quality > .ai-pilled/quality.json
python scripts/run_e2e.py
```

Check each command's exit status; do not continue past a failed bootstrap and claim
successful parity. `quality` already runs the complete test suite and regenerates
coverage; the dedicated E2E invocation additionally exports JSON/JUnit evidence.
Fixtures use local bare remotes and controlled registry responses. The quality audit
separately contacts PyPI for the actual selected development pins.

Fresh Python 3.10 tool environments passed all seven gates and the four E2E scenarios.
The same shared scenarios and quality profile passed with Python 3.14. The retained
pre-ancestry-fix local CI coverage artifact measured 2,702 of 2,967 lines (91.07%).
That measurement belongs to its recorded snapshot, not every later commit.

## Hosted acceptance still required

Once a credential with the necessary workflow capability is available, publish the
reviewed workflow through the normal Git process and inspect both matrix jobs. Confirm
that all seven gates and four E2E scenarios ran, download the four evidence files,
and test a deliberately failing proposal in a disposable branch. Configure required
hosted checks separately if desired. Local hooks and successful YAML parsing do not
establish server branch protection or remote pipeline success.
