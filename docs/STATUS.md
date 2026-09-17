# Feature status and evidence

Updated 2026-09-16. The source of feature intent is [FEATURES.md](FEATURES.md),
not claims made by the original scaffold. This report distinguishes implemented
behavior, reproducible tests, actual activation, and work still needed.

The verification baseline is `1878a39`: 711 tests and seven configured quality gates
passed through the active Python 3.14 staged review. Prepared CI snapshot `9298609`
passed the same quality profile and all six E2E scenarios on Python 3.10. An actual full-audit of `1878a39` also passed all seven gates with zero
model workers. Comprehensive
staged review and Python dependency auditing are enabled in this repository.
GitHub workflow publication is blocked by the current login's missing `workflow`
scope. GitLab pipelines are **planned and deferred at the user's request**.

Python-literal credential inspection adds mandatory parsing to secret scans. Dogfooding
at `1ad8ac4` caught a performance-budget failure: 0.272 seconds median versus the unchanged
0.166-second baseline (64.1% increase; 20% budget). Profiling attributes the extra
work to parsing/traversing Python source. Security coverage is retained; performance
acceptance remains open, and the saved baseline has not been raised. Loading only the
selected CLI command and skipping literal-free AST identifier leaves reduced the
follow-up median to 0.211 seconds (27.5% over baseline). An earlier cold-start rerun
measured 0.216 seconds (30.3% over baseline). A subsequent rerun at `2e32729`
measured 0.244 seconds (47.4% over baseline). At `d337655`, the cold-start median
was 0.255 seconds (54.0% over baseline). An idle rerun at `b80ffda`
measured 0.273 seconds (65.1% over baseline), with the saved baseline verified
byte-for-byte unchanged. After raw-prefix filtering, the latest idle rerun at
`46f203c` measured 0.253 seconds (52.6% over baseline); the baseline remains
byte-for-byte unchanged and the 20% budget still fails. Separately, reusing
the same per-file AST for credential and pattern checks reduced five-run in-process
comprehensive-scan medians from 0.384 to 0.322 seconds with identical reports. That
improves comprehensive scans but does not turn the cold-start budget into a passing check.
A later JSON string-scanner experiment at `dbcdd8c` reduced seven-run staged scan
medians from 0.213 to 0.196 seconds (about 8%) with identical reports, 10,000
differential parser cases, and passing security/redaction fixtures. This is an
in-process comparison; the subsequent cold-start measurement above still fails.

A follow-up direct JSON-string slicing experiment at `ca66a59` showed no meaningful
improvement (203.481 versus 203.506 ms across seven alternating runs), despite
identical reports, 10,000 differential cases, and 72 passing security/redaction tests.
It was discarded; no extra parser path or raised performance baseline was introduced.

A bounded literal-result cache experiment at `b80ffda` was also discarded: seven
alternating scans measured 210.647 ms without it and 214.442 ms with it. Reports
were identical and 76 security/redaction fixtures passed, but the cache added cost.
No literal cache was added to the product.

A retained raw-text prefix filter measured 214.374 versus 189.543 ms at `424d02f`
across seven alternating in-process scans (11.6% improvement), with identical reports,
797 literal comparisons, and 76 existing security/redaction tests. It skips a raw-text
pattern only when its required case-sensitive substring is absent. Case-insensitive
AWS secret matching, unlisted rules, and all decoded-string checks still run. New
fixtures cover every current prefix variant, fully escaped equivalents, source lines,
and unlisted-rule fallback; all 78 related tests pass on Python 3.10 and 3.14. This
measurement does not itself satisfy the separate cold-process performance budget.

An idle cold-process rerun at `37d2ef8` measured 0.260 seconds, 56.8%
over the unchanged baseline. Profiling still identifies Python parsing and AST
traversal as major costs. An isolated traversal experiment measured 194.661 versus
187.899 ms over seven alternating in-process runs, with identical reports and 78
passing security/redaction tests. That small improvement was not adopted; it does
not resolve the cold-process budget.

Explicit urllib3 `assert_hostname=False` and proxy hostname overrides now produce
review warnings, including imported aliases and literal keyword dictionaries.
Dynamic or invalid explicit values remain incomplete; omitted settings, `None`, and
literal hostname strings remain allowed. Fingerprint pinning can be deliberate, so
these findings request peer-identity policy review rather than assert an exploit.
This rule covers explicit keywords on recognized managers, HTTPS pools and connections;
version-dependent positional hostname arguments and stored-instance mutation are not
traced. AST fixtures and a staged-versus-unstaged E2E scenario cover the behavior.
See the [urllib3 connection-pool contract](https://urllib3.readthedocs.io/en/latest/reference/urllib3.connectionpool.html).

The shell-vector reviewer also checks explicit `input=` supplied to a recognized
POSIX shell by `subprocess.run` or `check_output`, including scalar executable names,
`-s`, `+` option toggles, option separators, aliases and literal keyword dictionaries. Passing data to
a named script or a non-shell program remains outside this signal. A standalone
noninteractive `-n` syntax check is allowed; the repo's own hook-protocol test exposed
and now guards this false-positive boundary. Separately stored
`Popen` objects and later `communicate()` calls are not traced. This is a shell-use
review signal, not a proof that supplied commands are hostile. Source-only fixtures
and a real staged Git-hook scenario cover the distinction. The behavior follows
[Python's input forwarding](https://docs.python.org/3/library/subprocess.html) and
[Bash invocation rules](https://www.gnu.org/s/bash/manual/html_node/Invoking-Bash.html).

Environment-secret logging checks now follow direct text/byte conversions,
`.encode()`, `.decode()`, `.hex()`, and recognized Base16/32/64/85 or binascii
wrappers, including nested calls, aliases and keyword inputs. Encoding does not
redact the value. Ordinary non-credential environment keys, length-only metadata,
custom redactors and digest calls remain outside this rule; this is bounded expression
inspection, not general assignment or object data-flow analysis. Source-only fixtures
and staged Git-hook E2E coverage exercise these boundaries without reading real secrets.
See [Python's reversible encodings](https://docs.python.org/3/library/base64.html)
and [binary conversions](https://docs.python.org/3/library/binascii.html).

The current validation refresh at `1878a39` includes 711 tests and a passing actual
full audit with all seven nested quality gates and zero model workers. Prepared local
CI `9298609` passes the same gates plus six E2E scenarios (6.684 seconds, no failures,
errors or skips), with 3,983 of 4,288 lines covered (92.89%). Its branch is preserved
in both checkouts. The subsequent idle cold benchmark measured 0.262 seconds, 58.3%
over the byte-for-byte unchanged baseline: performance remains failed at the original
20% budget and is the sole currently generated follow-up. None of this constitutes a
hosted GitHub/GitLab run or live integration delivery.

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
Git blobs. Python literal and pattern checks cover `.py`, `.pyw`, `.pyi`, and
files with a Python-identifying shebang, including extensionless entrypoints.
This detects common Python/PyPy interpreter names and env wrappers without executing
them; arbitrary launcher aliases and Python code without a suffix/shebang remain outside
detection. Worktree reads open each relative directory through anchored descriptors
with no symlink following, so a parent symlink swap cannot redirect a file read outside the
repository. They compare descriptor identities before/after reading and
verify the path still names that file, rejecting observed edits, replacements, deletions,
permission changes, and symlink swaps. This prevents stale-descriptor false passes;
it does not claim an atomic repository-wide snapshot. ASCII token boundaries prevent non-ASCII neighboring bytes or text from
hiding recognizable credentials in scans or redacted output. Quoted JSON strings are decoded once for Unicode/slash escapes, including
values hidden by duplicate keys; malformed literals do not suppress raw scanning.
Plaintext AWS assignments span whitespace/parentheses and support simple str/bytes
annotations, named-expression operators, and literal string prefixes. Scans locate
the credential's value line; shared redaction masks these forms in messages/output.
AWS secret-key field names are paired with their decoded JSON values, including
escaped keys and duplicate entries. The shared redactor handles nested dictionary fields
and masks those values while retaining JSON keys/quoting and unrelated data. Complete
private-key block redaction still precedes individual quoted-string handling.
This is direct string-escape handling, not arbitrary encoding or runtime data-flow analysis.
PyPI publishing tokens follow the provider’s documented prefix and minimum
payload length; the shared pattern also redacts reports/history and blocks credential-like
package identities before registry queries. Recognizable GitLab `glpat-` access tokens
and Stripe secret/restricted live/test keys plus organization keys are also scanned
and redacted across reports, history, and dashboards. These patterns use conservative
minimum payload lengths (20 for GitLab, 24 for Stripe), not online validity checks;
custom token formats remain outside their coverage. Stripe publishable keys are allowed.
Provider distinctions: [GitLab token overview](https://docs.gitlab.com/security/tokens/)
and [Stripe key types](https://docs.stripe.com/keys).
Python string/byte constants are parsed without
execution, including adjacent literals and Python escapes; findings cite the start of
the source literal. The shared text matcher also detects and redacts contiguous AWS secret values in
YAML literal/folded block scalars (including header comments, indentation, and
chomping indicators) and triple-quoted configuration strings, reporting the value's
source line. This is a credential heuristic, not a complete YAML/TOML parser;
alias resolution and arbitrary split/escaped configuration values are not evaluated.
A stress test caught overlapping whitespace repetition in the initial multiline
matcher; the fix scopes whitespace to the optional block header. A timeout-bounded
regression scans and redacts 100,000-character whitespace inputs and malformed headers.
This protects review responsiveness while retaining the existing positive cases.
See [YAML block headers](https://yaml.org/spec/1.2.2/#811-block-scalar-headers)
and [TOML strings](https://toml.io/en/v1.0.0#string).
Direct AWS secret fields are also paired with literal values in
assignments, annotations, named expressions, dictionaries, keyword arguments, and
function defaults. Multiline parentheses, adjacent strings, byte strings, and Python
escapes cannot hide a recognized field's literal value; arbitrary variable data flow
and destructuring assignments remain outside this context check. Parser warnings are suppressed because Python can echo an
unredacted source line; syntax failures still yield incomplete evidence. Runtime string
computations and arbitrary encodings are not evaluated. History caches separate
Python interpretation from identical non-Python blobs. Strict Python AST checks flag environment dumps, unsafe parsing, shell
execution (including implicit shell APIs and literal truthy shell flags), unsafe YAML
single/multiple-document loaders, weak cryptographic patterns, and explicit TLS-verification bypasses in
Requests/HTTPX APIs or the unverified SSL context factory, including import aliases.
Explicit urllib3 `cert_reqs` bypasses are checked in pool/proxy constructors,
HTTPS connections, and TLS helpers, including aliases, literal keyword mappings,
and supported positional arguments. Zero, `CERT_NONE`, and `NONE` produce review
errors; unresolved modes/expansions produce incomplete evidence. Defaults and
recognized verified modes remain allowed. This does not infer stored instance state
or certify arbitrary custom SSL contexts. Semantics follow the [urllib3 utilities](https://urllib3.readthedocs.io/en/stable/reference/urllib3.util.html)
and [certificate guidance](https://github.com/urllib3/urllib3/blob/main/docs/user-guide.rst).
Requests also rejects literal zero/empty verification values, which disable certificates;
`None` retains Requests defaults and remains allowed.
Import lookup separates module, function, class, lambda, and comprehension bodies, including aliases
in defaults and enclosing closures. Comprehension bodies skip class imports, their first
iterable uses the containing scope, and loop targets remain local, following the
[Python scope rules](https://docs.python.org/3/reference/expressions.html#displays-for-lists-sets-and-dictionaries).
Unrelated nested imports cannot hide outer calls;
relative imports are not treated as public packages. Literal absolute runtime imports through
`__import__`, `builtins.__import__`, `importlib.__import__`, and
`importlib.import_module` also resolve known unsafe calls. The resolver distinguishes top-level `__import__` results from nonempty
`fromlist` and `import_module` results. Unknown/relative targets, levels, fromlists,
and expansions produce incomplete evidence. It never loads the inspected modules
or evaluates source expressions. See [Python import semantics](https://docs.python.org/3/library/functions.html#__import__)
and [importlib](https://docs.python.org/3/library/importlib.html#importlib.import_module). Direct `Unpickler(...).load()`
and Requests `Session().get/post/request(...)` calls receive the same checks as their
module-level forms, including imported aliases. This does not resolve instances stored
in variables or infer whether a custom unpickler subclass is safe. Scientific package
signals cover `joblib.load`, `pandas.read_pickle`, NumPy loading with a literal truthy
`allow_pickle`, and PyTorch loading with an explicit falsey `weights_only` other than
`None`. Aliases, literal mappings, and NumPy's positional option are inspected;
unknown supplied options are incomplete. This neither imports those packages nor
loads artifacts. Unspecified PyTorch defaults vary by version/environment, and a
restricted option is not proof that an artifact or installed library is safe.
References: [Joblib warning](https://joblib.readthedocs.io/en/stable/generated/joblib.load.html),
[Pandas warning](https://pandas.pydata.org/pandas-docs/stable/reference/api/pandas.read_pickle.html),
[NumPy options](https://numpy.org/doc/stable/reference/generated/numpy.load.html), and
[PyTorch loading](https://docs.pytorch.org/docs/stable/generated/torch.load). Shell rules include `os.popen`,
`subprocess.getoutput/getstatusoutput`, and `asyncio.create_subprocess_shell`; YAML
rules include `unsafe_load`, `unsafe_load_all`, and `load_all` without an explicit safe loader.
Explicit `yaml.loader.SafeLoader` and `yaml.cyaml.CSafeLoader` imports are recognized;
fallback imports are accepted only when every alternative is a recognized safe loader.
Mixed or unsafe loader aliases remain blocked. Requests' lowercase `session()` factory also
receives TLS checks. Weak-hash notices cover keyword `hashlib.new(name=...)` calls
and retain the explicit `usedforsecurity=False` exemption.
Environment-dump checks include literal string formatting, serialization keyword arguments,
and environment value/item views, including starred arguments and byte environments.
Logging methods are inspected on factory-returned loggers/adapters and logger parameters
as well as named logger variables.
Credential-named literal lookups through `environ`, `environb`, `getenv`, and `getenvb`
are blocked at logging calls. Mapping `pop`, `setdefault`, and direct `__getitem__`
lookups are included, along with immediate `.copy()` results used for lookups,
subscripts, or value/item views. Positional fallbacks and `setdefault(value=...)`
are inspected. Ordinary metadata, keys-only views, and non-logging uses remain
allowed; separately stored copies are not traced. Source-only fixtures and staged
E2E checks cover these paths without reading or modifying the real environment.
See [Python environment mappings](https://docs.python.org/3/library/os.html#os.environ).
Names ending in TOKEN, SECRET, PASSWORD, API_KEY, or
PRIVATE_KEY, plus AWS access/secret key names, are review signals; ordinary HOME/PATH
and metadata names remain allowed. Lookup fallbacks, conditional result branches,
boolean results, and assignment expressions are inspected; condition-only credential
checks do not expose their value. This does not trace separate assignments or arbitrary data flow.
Temporary-name checks reject `tempfile.mktemp()` and import/getattr aliases while
allowing atomic temporary-file constructors. PyJWT `decode`/`decode_complete` module
calls reject literal falsey `options.verify_signature`, including positional options,
expanded mappings, and aliases. Unknown supplied options or verification expressions
produce incomplete evidence; literal dictionary overrides retain last-key semantics.
These checks do not trace separately stored decoder instances or certify claim policy.
References: [Python temporary-file warning](https://docs.python.org/3/library/tempfile.html#tempfile.mktemp)
and [PyJWT signature options](https://pyjwt.readthedocs.io/en/latest/usage.html).
Literal POSIX shell command vectors (`sh`, `bash`, `dash`, `ksh`, `zsh` with `-c`,
including combined flags) are reviewed in subprocess and asyncio exec APIs even
without `shell=True`. Literal executable overrides and argument expansions are included.
Unknown options on a known shell are incomplete; `--` separates script arguments.
Wrapper programs, runtime program names, and shell script bodies are not inferred.
See [Bash invocation](https://www.gnu.org/s/bash/manual/html_node/Invoking-Bash.html).
Tar extraction checks inspect known `TarFile.extract`/`extractall` methods and
immediate `tarfile.open`, `TarFile`, or `TarFile.open` results. Explicit
`fully_trusted` strings or callbacks require review; unknown/custom filters and
implicit/None defaults produce incomplete evidence because runtime and instance policy
matter. Named `data` and `tar` filters are recognized, without claiming that either
makes every archive safe. Aliases, literal mappings, conflicting filter imports, and
staged unsafe calls hidden by unstaged fixes have coverage on Python 3.10 and 3.14.
Separately stored archive instances are not traced. Python changed the default to
`data` in 3.14; see [extraction filters](https://docs.python.org/3/library/tarfile.html#extraction-filters).
Ordinary argument-array subprocess APIs and explicit safe YAML loaders remain allowed. Other referenced conflicting imports
in one scope are incomplete. Verified defaults and literal custom CA paths remain allowed. Explicit dynamic shell
flags and TLS verification flags/contexts produce incomplete evidence; the reviewer
does not infer their runtime values or certify separately constructed SSL contexts.
Unverified TLS factory review includes the stdlib compatibility alias. Direct and
annotated assignments, plus literal `setattr` calls, that replace
`ssl._create_default_https_context` with a known unverified factory are blocked.
Unknown replacement factories are incomplete; verified restoration and a no-op
assignment remain allowed. Import aliases and literal argument expansion are covered,
including staged overrides hidden by unstaged restoration. These are source-only
checks; they do not mutate TLS policy or trace arbitrary factory assignment chains.
References: [CPython SSL factories](https://github.com/python/cpython/blob/main/Lib/ssl.py)
and [PEP 476 opt-out behavior](https://peps.python.org/pep-0476/#opting-out).
Literal starred lists and tuples are expanded iteratively for inspected arguments,
including nested expansion. Positional subprocess shell flags receive the same review
as keyword flags; unresolved positional expansions in subprocess/PyJWT security calls
are incomplete. Literal expansion also preserves environment-lookup, YAML-loader,
and weak-hash checks without running source expressions.
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

Codex hook installation also creates ownership metadata exclusively and checks bounded
configuration snapshots immediately before publication. Detected concurrent edits and
symlink replacements are preserved. Failed writes remove only unchanged metadata owned
by that attempt; uncertain successful publication retains it for recovery. Uninstall
checks both snapshots before rewriting and preserves changed metadata before deletion.
These checks do not make the two files an atomic transaction or prevent every race by
noncooperating writers. Regression tests cover concurrent edits, metadata replacement,
write failure, uncertain completion, and symlink targets on Python 3.10 and 3.14.

**Activation / limits:** Git commit/push scanning is active here. Codex hook files
are installed, but live trust/activation has not been verified. A manual lifecycle
smoke test passed. AST checks are conservative Python patterns, not whole-program
analysis; other languages currently receive credential checks. Literal `**{...}` keyword
mappings are inspected for TLS, shell, YAML-loader, and hash settings, including nested
mappings and later-key overrides. Opaque keyword expansions at those security-sensitive
calls report incomplete evidence; they are never evaluated to discover runtime values.
Literal `getattr` names retain the same checks, including imported built-in aliases;
parameter-shadowed or unrelated functions are not treated as the built-in. Wildcard
imports produce incomplete binding evidence instead of a false clean review. Arbitrary
attribute expressions and general assignment data flow remain outside this analysis.
Leak checks inspect eager comprehension result values and generators consumed by
list/tuple/set/dict, starred print arguments, or string joining. Import aliases retain
these checks. Merely logging a generator object, a comprehension filter condition, or
an iterable whose values are not returned is not treated as exposing its secret values.
Environment leak checks also cover standard output/error stream writes (including
binary buffers and original streams), display hooks, warning calls, and logging's
`warn`/`fatal` aliases. `writelines` inspects consumed generator values; unrelated or
shadowed stream bindings are outside that rule.
Dictionary overwrite semantics follow the [Python language reference](https://docs.python.org/3.10/reference/expressions.html#dictionary-displays). An after-tool hook
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

Commit-hook selection now reads the resolved regular policy blob from the index,
with a 64 KB bound and the same strict configuration schema. Unstaged opt-outs cannot
disable staged comprehensive checks, strict patterns or selected model review.
The staged reviewer also takes its configured executable and timeout from that policy;
an explicit CLI executable override remains available. An absent staged policy uses
defaults, so new local policy must be staged to affect commit gates. Conflicted,
symlink, malformed and oversized policy entries block rather than choosing a working
copy or conflict side. Actual disposable Git commits reproduce each opt-out bypass;
no live model was invoked during these regressions.

The commit-msg hook checks conventional subjects, length, and credentials. Optional
model review checks message alignment and concrete correctness/security defects. It
uses the existing Codex subscription login, a bounded staged snapshot, read-only mode,
disabled hooks, a restricted environment, and validated structured source locations.
Review preparation rejects more than 2,000 staged files before reading blobs, retains
the 2 MB per-file and 20 MB total limits, and uses the shared bounded Git batch reader.
Missing or oversized blobs cannot produce a partial successful snapshot. Binary bytes
and executable modes are preserved. A five-pair prototype measurement on the 93-file
`8d0c4bd` snapshot reduced preparation medians from 385 to 234 ms with identical
manifests; this is preparation timing, not the cold-start scan budget.
Model output uses bounded regular-file reads without following final symlinks.
Cited source opens each relative directory beneath the supplied snapshot without
following symlinks and compares file identities during and after the bounded read.
Parent-directory swaps and observed replacements cannot validate an outside or stale
source line. This is a read-time consistency check, not an atomic filesystem snapshot.
`review --comprehensive` requires deterministic evidence and model findings to refer
to the same index.
Each materialized index also returns a manifest of original file hashes, sizes, and
permissions. Citations in both review paths must belong to that original manifest;
a file introduced by a reviewer cannot be accepted merely because it exists. Relative
path spelling is normalized, preserving legitimate `./` and repeated-separator citations.
Fake providers exercise added-file rejection and whole-response invalidation without
starting a live model. Review and full-audit perspectives verify those supplied files before
and after model invocation, even when the model returns no findings. Changed bytes,
permissions, missing files, and symlink substitutions make evidence incomplete.
Fake-reviewer mutation and pre-invocation corruption fixtures exercise this boundary;
no live model call was made. This detects observed changes to supplied files, not
transient edits restored between checks or every added untracked file.

**Evidence:** `test_staged_review.py`, `test_git_hooks.py`, `test_codex_review.py`,
and the partial-staging E2E case. The new reviewer passed its own staged implementation.
A real installed Codex CLI caught a seeded defect in an earlier smoke test. Current
multi-reviewer behavior has fixture coverage only; no new model workers were started.
Full audits pin HEAD across quality and review, reject assume-unchanged/skip-worktree
flags before model use, and recheck actual source afterward; hidden or committed
replacements cannot combine old quality evidence with a different reviewed snapshot.
Model-review counts reflect invocation attempts, including failed invocations; a
perspective blocked by source preflight counts zero. These metrics do not claim a
provider successfully completed a review.

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
Historical cache keys now use the central Python-source classifier, separating `.py`,
`.pyw`, and `.pyi` interpretation from plain text; shebang behavior remains tied to
the blob content. A regression reproduced a real local push of an encoded credential
from a subsequently removed `.pyw` file when an identical text blob primed the cache.
That push is now rejected, with the remote ref unchanged. Both cache orders, all
Python extensions, and shebang paths have coverage on both supported runtimes.

**Evidence:** `test_pre_push.py` plus actual local bare-remote E2E pushes. Protected
branch and failing-test rejections leave remote refs unchanged. Regression fixtures
cover historical secrets, replacement refs, malformed updates, and changed evidence.
Normal development pushes use the installed hook; it has not been bypassed.

**Limits / acceptance:** local hooks are user-bypassable. Server branch protection and
required hosted checks are separate controls and have not been configured or claimed.

Pending repository policy cannot authorize a push. Preflight now rejects staged,
unstaged, deleted, untracked or ignored `.ai-pilled.json` changes before loading the
policy, and checks hidden index flags before evaluating deletion updates as well.
A local bare-remote regression reproduced a protected-branch push bypass through an
unstaged test/protection opt-out; the push is now rejected. A committed test opt-out
still permits unrelated pending work, and no-op pushes do not run checks. These are
local cooperative gates; they do not replace hosted branch protection or prevent a
user from editing/disabling installed hooks.

### 4. Dependency auditing — npm and Python implemented; Python active here

The npm manifest and selected lockfiles now receive bounded, identity-checked reads
and credential inspection before any audit or health provider is invoked. Raw,
JSON-escaped, UTF-16 and UTF-32 recognizable credentials block the operation with a
generic diagnostic; input contents are not copied into reports or history. License
checks use the same preflight. Regression fixtures cover all three selected input
names and replacement during a read. These checks do not establish whole-repository
atomicity or detect every possible credential format.

Python requirement inputs use descriptor-relative, no-symlink reads and identity
checks during and after reading. Observed parent substitutions, replacements, and
mutations are rejected before invoking pip-audit, preventing the reproduced outside-pin
submission. This is bounded snapshot checking, not an atomic filesystem transaction.

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
preserved. Malformed error flags or exit codes cannot certify success; a null exit
without a live command session remains unknown/wait. Explicit failures retain failure
status even when another marker is malformed, and a valid completion code still
supersedes a retained session identifier. Stop-hook recursion metadata must be a real boolean; strings such as
`"false"` cannot suppress a blocking result and are rejected before configured tests run.
Summaries, dashboard counts, and suggestions share bounded traversal of
nested check/step results; a newer child result supersedes older evidence for that check.
A passing parent cannot hide a failed child. Each recorded check must also agree with its own findings: error findings cannot report pass/incomplete, and warning findings cannot report pass. Malformed or contradictory evidence stops summaries, suggestions, and dashboard publication; existing dashboard output is preserved. Legacy records without finding severities remain readable only when already blocked. Raw tool transcripts are not retained in the summary/history.

**Evidence:** `test_lifecycle.py`, `test_reporting.py`, and real CLI E2E checks.
History reads and appends open the state directory through a root-relative descriptor,
so a swapped `.ai-pilled` parent cannot redirect an append, change an outside file's
mode, or supply outside check records. Existing lock, regular-file, hard-link, and
size checks still apply. Dashboard temporary files and publication use the same
root-anchored writer as README updates, followed by a bounded content recheck.

Dashboard counts, headline, and rows derive from one captured history read. An append
while rendering becomes visible on the next generation, rather than mixing an older
success summary with newer failed rows. Historical evidence still does not certify
current source files.

The dashboard escapes content, uses a restrictive content policy, and writes private
output atomically. Symlinks/special files cannot redirect dashboard writes.

**Limits:** no unsupported batch-completion event is claimed. Historical success does
not certify later changes. Browser rendering has not been verified. The `suggest` command prioritizes recorded failures and missing feature configuration,
provides explicit check argument lists, and labels historical evidence. It is read-only;
external actions are never replayed automatically. Nested newer check results supersede
older child results; priority, bounds, redaction, and no-execution tests are in
`test_suggestions.py`.

Benchmark locks and baseline reads are anchored beneath the repository. Explicit
baseline saves use descriptor-relative publication and recheck the written data.
A state-directory swap cannot create an outside lock, supply an outside baseline,
or overwrite an outside baseline file. These guards do not change the saved budget;
security fixtures use synthetic timings and disposable baseline files.

An earlier scan benchmark at `ac70b2a` passed its unchanged 20% budget: three-run
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
| 6 | Coverage — active | Fresh coverage.py JSON and 80% line minimum; root-relative no-symlink reads and descriptor/current-path identity checks reject observed evidence changes; exact line-count comparisons against decimal thresholds avoid floating-point boundary errors; `test_metrics.py`, `scripts/check_coverage.py` | Line coverage is not branch coverage or a correctness proof. |
| 7 | Performance regression — opt-in | Repeated process timing, median baseline, host/command identity; `test_performance.py` | Explicit baseline replacement; machine-dependent measurements, not application profiling. Latest recorded cold scanner comparison: 262 ms vs 166 ms baseline, 58.3% over baseline; the 20% budget fails. |
| 8 | Bundle size — opt-in | Existing artifact byte budgets; path/link/bounds tests in `test_metrics.py` | Does not build artifacts or infer a product-specific budget. |
| 9 | Changelog — implemented | `release-plan`, bounded explicit conventional-commit range with raw ancestry verification (truncated shallow history is incomplete); `test_releases.py` | Inspect generated notes; no automatic publication. |
| 10 | README updater — used here | Generated CLI block with drift check; `test_documentation.py` | Handwritten prose is preserved; detected concurrent content, identity, or permission changes block publication. Documentation correctness is not inferred. |
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
| 23 | Nightly refactoring — implemented, inactive | Timezone-aware daily attempts, root-anchored locks and persisted deduplication, verified reservation before work, foreground watch; `test_scheduling.py` | Controlled-clock DST/restart/failure, parent-swap, and calendar-boundary tests. No recurring process installed. |
| 24 | Self-healing — opt-in | `heal`: verify one-commit reversal, full quality, reproduce original failure again; `test_healing.py` | Preview default; explicit apply creates a normal local revert. Real mutations tested only in disposable fixtures; no automatic production rollback. |

## CI and end-to-end evidence

`python scripts/run_e2e.py` runs six multi-step scenarios through the real CLI:

1. Install hooks, commit, push to a local bare remote, consume lifecycle events,
   summarize results, and generate the offline dashboard.
2. Reject a bad subject, a staged credential, a TLS bypass hidden by an unstaged fix,
   implicit shell/unsafe YAML APIs hidden by unstaged fixes, and a failing test hidden by partial staging;
   confirm HEAD does not move.
3. Reject hidden worktree changes, a protected destination, and a failing-test push; confirm remote refs do not move.
4. Run Python audit/lifecycle through a fixture provider; preserve vulnerability and
   incomplete statuses, including cache behavior.
5. Run a full audit without model workers, plan a release, preview all four notification
   providers without credentials, and enforce coverage/artifact budgets through the CLI.
   Confirm HEAD, tags, working files, and remote refs remain unchanged by previews.

6. Block staged extensionless/Windows Python entrypoints and dynamic shell/TLS
   settings despite clean worktree copies, then commit and push the staged fixes
   to a local bare remote; verify its exact HEAD.

All six passed on Python 3.10 and 3.14. The runner produces private
`.ai-pilled/e2e.json` and `.ai-pilled/e2e.xml` with every test outcome. Exported artifacts
contain named outcomes rather than raw process transcripts. The E2E repository uses
small configured lint/type/deadcode/coverage fixture commands; the actual development
quality run separately exercises Ruff, mypy, Vulture, and fresh coverage.

| Pipeline | Status | Evidence / blocker |
| --- | --- | --- |
| Local quality and staged review | Active | Seven gates: security, tests, Ruff (syntax/imports plus bugbear and Bandit), mypy, Vulture, fresh coverage, live Python dependency audit. Missing tools/registry evidence block. |
| Local shared E2E | Verified on 3.10 and 3.14 | Real Git/CLI workflows; registry response fixtures explicitly distinguished from live audit evidence. |
| GitHub Actions | Prepared and locally validated at `9298609`; publication blocked | Current 3.10 seven-gate/E2E evidence, 92.89% coverage, hash-enforced development and auditor bootstraps, immutable action pins, and explicit artifacts are documented in [CI.md](CI.md). GitHub rejected publication after pre-push passed because the login lacks workflow scope. No hosted run or required-check activation is claimed. |
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

Performance follow-ups now offer a repository-bound benchmark rerun with the recorded
run count and budget, after validating both. They do not save a baseline or run the
command automatically; missing configuration or malformed measurements require inspection.

Pre-push input is capped before Git or network work: at most 1,000,000 text characters
and 2,000 ref updates. Oversized input is rejected without echoing it; the CLI reads
only enough to detect the limit. Invalid stream encodings become structured protocol
errors for both pre-push and lifecycle input. Existing commit/history bounds still apply.

Bundle content reads use anchored directory descriptors and reject parent symlinks,
including swaps during inventory construction, before reading outside file content.
Bundle measurement rejects unreadable or interrupted directory listings instead of
silently omitting their files. Traversal is capped at 10,000 entries including the
selected root and empty directories, in addition to the existing 100 MB read limit.
Entry identities are captured during traversal and compared with each open descriptor
before and after reading. A second bounded inventory rejects added, removed, replaced,
modified, or permission-changed entries before publishing byte metrics. A fixture that
previously passed with 1 byte while a concurrent build added another 100 bytes is now
incomplete. These checks detect observed build changes, not every hostile filesystem race.
Partial traversal never publishes byte metrics. Filesystem filename bytes are retained
in the fingerprint, including non-UTF-8 names; measurements do not rename input files.

Root-relative file reads and publication share the directory-descriptor traversal
helper, retaining the same symlink rejection and descriptor cleanup rules.

Refactor and healing patch exports share the root-anchored publication helper,
preserve binary bytes and private mode, use exclusive final names, and verify the
exported bytes before returning a path. Parent swaps cannot redirect the export;
failed writes clean their temporary file without publishing a partial patch.
A candidate already published in the original directory can remain after a late
path change, which is reported as incomplete. No live refactor/healing action was
performed for these guards; binary, collision, race, and failure fixtures cover them.

Disposable refactor/healing checkouts also hold their state-directory descriptor
through creation, child commands, and cleanup. On Linux, a path through the running
parent process's `/proc/<pid>/fd` entry keeps these operations on that directory
when its original path is replaced. Missing or inaccessible proc descriptors fail
closed. Real Git fixtures pass on Python 3.10 and 3.14; race fixtures preserve outside
directories and confirm private workspace mode, child access, cleanup, and descriptor
closure. This is path confinement, not a sandbox for configured commands or protection
against every mutation by another process with the same user permissions. See
[Linux proc descriptor semantics](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html).

README reads and publication are now anchored beneath the selected repository.
Temporary creation, rename, exclusive publication, and cleanup use one opened parent
directory descriptor. Replacing a parent with an outside symlink cannot redirect the
write; a post-publication identity check reports observed replacements as incomplete.
A candidate already published in the original directory may remain for inspection.
Nested destination creation, handwritten prose, modes, and the drift-check command
remain supported. This does not provide an atomic transaction across concurrent edits.

README and release generation use bounded descriptor snapshots and reject changes
during a read. Release preparation checks HEAD and all expected metadata immediately before
each publication. Rollback restores only files whose identity and contents still match
this attempt's output, preserving detected concurrent edits. Uncertain publication or
failed restoration reports incomplete evidence and requires file inspection; these
two-file updates are not claimed to be fully atomic. Tests exercise second-write
failure, edits before publication/during rollback, and lost completion after a write.
Release publication reads the exact remote `refs/tags/...` reference, rather than
resolving an ambiguous branch/tag name through the commit API. Annotated tags are
peeled with validated object identities, cycle rejection, and a 16-annotation limit;
only the selected commit is accepted. Verification repeats immediately before creation
and after the provider response. Fixtures cover same-named branch evidence, malformed
objects, moved tags, nested annotations, and chain boundaries. These repeated checks
detect observed movement; they cannot make separate GitHub requests transactional.
Release confirmation also requires a valid publication timestamp with a timezone.
Auto-merge confirmation requires an integer PR identity plus the requested squash
method and a valid enabled timestamp; a merged outcome needs a full merge-commit
identity and valid merged timestamp. Empty or contradictory provider objects stay
unconfirmed. Merge queues that substitute another method require manual inspection;
this client does not certify that a separate server action followed the requested method.
No live release was prepared or published during this hardening work.

Performance evidence rejects invalid numeric budgets, nonpositive/nonfinite timings,
and overflowed medians or comparisons. Extreme finite baselines cannot create infinite
report values, and failed measurements do not replace the saved baseline. History
serialization independently rejects nonfinite numbers before opening its file, so
invalid nested metrics cannot poison otherwise readable history. Serialized records
also pass the reader's nesting and unique-key validation before append; encoding-time
key collisions and excessive nesting leave existing history untouched. A complete
final record without a newline is validated and separated before append; malformed
or oversized partial tails are preserved and rejected. Separator bytes participate in
history rotation's size budget.

Model review also preflights touched historical blobs through a conservative removal
view before exporting a diff. Redaction is rescanned using decoded Python/JSON checks;
remaining credentials, invalid Python after redaction, unreadable/oversized blobs, or
lost source boundaries block the model call. This intentionally requires local checks
for removals that cannot be safely represented. Historical inspection is capped at
2 MB per blob, 20 MB total, and 2,000 files. The diff uses a captured HEAD baseline,
which is rechecked before and after the model invocation. Fixtures capture prompts or
replace the reviewer; no live model worker was started for this hardening.

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
