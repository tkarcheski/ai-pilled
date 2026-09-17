"""Validate Git's actual ref updates, not shell-command guesses."""
import fnmatch
import re

from .checks import command_check, require_visible_index
from .config import load
from .commit_messages import check_subject
from .runtime import CommandError, Report, run
from .security import MAX_FILE_BYTES, scan, scan_text, scan_bytes, scan_path
from .python_security import inspect_python, is_python_source

OID = re.compile(r'[0-9a-f]{40}(?:[0-9a-f]{24})?')
MAX_COMMITS = 2000
MAX_CACHE_ENTRIES = 10000
MAX_REMOTE_REFS = 2000
MAX_UPDATES = 2000
MAX_UPDATE_CHARACTERS = 1_000_000


def read_updates(stream):
    try:
        updates = stream.read(MAX_UPDATE_CHARACTERS + 1)
    except UnicodeError as exc:
        raise CommandError('Pre-push input must be valid text') from exc
    if len(updates) > MAX_UPDATE_CHARACTERS:
        raise CommandError('Pre-push input exceeds the 1000000-character limit')
    return updates


def blob_findings(repo, oid, path, patterns, cache):
    # Shebang detection is fixed by the blob; extensions can change interpretation.
    key = (oid, is_python_source(path, b''), patterns)
    if key in cache:
        return cache[key]
    result = Report('blob-security')
    try:
        if int(run(['git', 'cat-file', '-s', oid], repo)) > MAX_FILE_BYTES:
            raise CommandError('File exceeds scan size limit')
        content = run(['git', 'cat-file', 'blob', oid], repo, limit=MAX_FILE_BYTES)
        tree = scan_bytes(result, path, content)
        if patterns:
            inspect_python(result, path, content, tree=tree)
    except CommandError as exc:
        result.add('scan-incomplete', str(exc), severity='warning')
    # Cache only location-independent findings, never credential-bearing source bytes.
    findings = tuple((f.rule, f.message, f.line, f.severity) for f in result.findings)
    if len(cache) < MAX_CACHE_ENTRIES:
        cache[key] = findings
    return findings


def scan_revision(repo, revision, patterns=False, cache=None, conventions=False, expected_parents=None):
    report = Report('history-security', snapshot=revision)
    cache = {} if cache is None else cache
    metadata = run(['git', 'cat-file', 'commit', revision], repo, limit=128_000)
    headers, separator, message = metadata.partition(b'\n\n')
    if not separator:
        raise CommandError('Cannot read complete commit metadata')
    raw_parents = [line[7:].decode('ascii', errors='replace')
                   for line in headers.splitlines() if line.startswith(b'parent ')]
    if expected_parents is not None and sorted(raw_parents) != sorted(expected_parents):
        report.add('history-incomplete',
                   'Outgoing ancestry is truncated; obtain complete history for this range and rerun.',
                   path='(commit ancestry)', severity='warning')
    identity: list[bytes] = []
    other: list[bytes] = []
    for line in headers.splitlines():
        (identity if line.startswith((b'author ', b'committer ')) else other).append(line)
    scan_text(report, '(commit message)', message.decode('latin-1'))
    if conventions:
        lines = message.decode('utf-8', errors='replace').splitlines()
        check_subject(report, lines[0] if lines else '')
    scan_text(report, '(commit identity)', b'\n'.join(identity).decode('latin-1'))
    scan_text(report, '(commit headers)', b'\n'.join(other).decode('latin-1'))
    records = run(['git', 'ls-tree', '-rz', '--full-tree', revision], repo).split(b'\0')
    for record in filter(None, records):
        metadata, raw_path = record.split(b'\t', 1)
        mode, kind, oid = metadata.split()
        path = raw_path.decode('utf-8', errors='surrogateescape')
        scan_path(report, path)
        if kind != b'blob':
            report.add('submodule-unscanned', 'Submodule content requires its own audit.',
                       path=path, severity='warning')
            continue
        for rule, message, line, severity in blob_findings(repo, oid.decode(), path, patterns, cache):
            report.add(rule, message, path=path, line=line, severity=severity)
    return report


def scan_tags(repo, oid):
    report = Report('tag-security')
    try:
        for depth in range(17):
            kind = run(['git', 'cat-file', '-t', oid], repo).strip()
            if kind != b'tag':
                return report
            if depth == 16:
                raise CommandError('Annotated tag chain exceeds the 16-tag limit')
            content = run(['git', 'cat-file', 'tag', oid], repo, limit=64_000)
            scan_text(report, '(tag metadata)', content.decode('latin-1'))
            headers = content.split(b'\n\n', 1)[0].splitlines()
            objects = [line[7:].decode('ascii') for line in headers if line.startswith(b'object ')]
            if len(objects) != 1 or not OID.fullmatch(objects[0]):
                raise CommandError('Cannot resolve annotated tag target')
            oid = objects[0]
    except (CommandError, UnicodeError) as exc:
        report.add('tag-unavailable', str(exc) if isinstance(exc, CommandError)
                   else 'Cannot read annotated tag metadata', severity='warning')
    return report


def published_commits(repo, destination):
    """Trust only refs advertised by this destination, never local tracking refs."""
    output = run(['git', 'ls-remote', '--refs', '--heads', '--tags', '--', destination], repo,
                 timeout=load(repo).timeout, limit=1_000_000)
    rows = output.splitlines()
    if len(rows) > MAX_REMOTE_REFS:
        raise CommandError('Remote advertisement exceeds the 2000-ref limit')
    objects = set()
    for row in rows:
        fields = row.split(b'\t')
        if (len(fields) != 2 or not OID.fullmatch(fields[0].decode('ascii', errors='replace'))
                or not fields[1].startswith((b'refs/heads/', b'refs/tags/'))):
            raise CommandError('Remote returned invalid ref evidence')
        objects.add(fields[0].decode('ascii'))
    commits = set()
    for oid in objects:
        # Missing local objects or non-commit tags cannot establish local ancestry.
        commit = run(['git', 'rev-parse', '--verify', '--quiet', oid + '^{commit}'], repo,
                     acceptable_codes=(0, 1, 128)).decode().strip()
        if commit:
            if not OID.fullmatch(commit):
                raise CommandError('Cannot resolve a published commit identity')
            commits.add(commit)
    return commits


def pre_push(repo, updates, destination=None):
    report = Report('pre-push')
    if not isinstance(updates, str) or len(updates) > MAX_UPDATE_CHARACTERS:
        report.add('update-input-limit', 'Pre-push input must be text within the 1000000-character limit.',
                   severity='warning')
        return report
    lines = updates.splitlines()
    if len(lines) > MAX_UPDATES:
        report.add('update-count-limit', 'Push exceeds the 2000-ref update limit; split the proposal.',
                   severity='warning')
        return report
    config = load(repo)
    head = run(['git', 'rev-parse', '--verify', 'HEAD'], repo).decode().strip()
    commits = set()
    tips = set()
    published = None
    traversed_parents: dict[str, list[str]] = {}
    for line in lines:
        fields = line.split()
        if len(fields) != 4:
            report.add('invalid-ref-update', 'Expected four fields from Git pre-push stdin.')
            continue
        local_ref, local_oid, remote_ref, remote_oid = fields
        if not OID.fullmatch(local_oid) or not OID.fullmatch(remote_oid):
            report.add('invalid-object-id', 'Git supplied an invalid object ID.')
            continue
        branch = remote_ref.removeprefix('refs/heads/')
        if remote_ref.startswith('refs/heads/') and any(
                fnmatch.fnmatchcase(branch, pattern) for pattern in config.protected_branches):
            report.add('protected-branch', f'Direct update to protected branch {branch} is blocked.')
            continue
        if set(local_oid) == {'0'}:  # Deletion has no code to validate.
            continue
        scan_text(report, '(destination ref)', remote_ref)
        if report.status != 'pass':
            continue
        try:
            metadata = scan_tags(repo, local_oid)
            for finding in metadata.findings:
                report.add(finding.rule, finding.message, path=finding.path, line=finding.line,
                           severity=finding.severity)
            tip = run(['git', 'rev-parse', '--verify', local_oid + '^{commit}'], repo).decode().strip()
            tips.add(tip)
            args = ['git', 'rev-list', '--parents', f'--max-count={MAX_COMMITS + 1}', tip]
            if set(remote_oid) != {'0'}:
                try:
                    old = run(['git', 'rev-parse', '--verify', remote_oid + '^{commit}'], repo).decode().strip()
                except CommandError:
                    old = None  # Missing remote history: conservatively scan all local history.
                if old:
                    args += ['^' + old]
            if set(remote_oid) == {'0'} and destination is not None:
                if published is None:
                    published = published_commits(repo, destination)
                args += ['^' + oid for oid in sorted(published)]
            rows = run(args, repo).decode().splitlines()
            outgoing = []
            for row in rows:
                fields = row.split()
                if not fields or any(not OID.fullmatch(oid) for oid in fields):
                    raise CommandError('Cannot parse outgoing parent evidence')
                outgoing.append(fields[0])
                traversed_parents[fields[0]] = fields[1:]
            if len(outgoing) > MAX_COMMITS:
                report.add('history-limit', 'Push exceeds the 2000-commit audit limit; audit a smaller range.')
            else:
                commits.update(outgoing)
                if len(commits) > MAX_COMMITS:
                    report.add('history-limit', 'Combined ref updates exceed the 2000-commit audit limit.')
        except CommandError as exc:
            report.add('history-unavailable', str(exc))
    if report.status != 'pass':
        return report
    blob_cache: dict = {}
    for commit in sorted(commits | tips):
        result = scan_revision(repo, commit, patterns=config.aggressiveness == 'strict' and commit in tips,
                               cache=blob_cache, conventions=commit in commits,
                               expected_parents=traversed_parents.get(commit))
        for finding in result.findings:
            report.add(finding.rule, f'{commit[:12]}: {finding.message}', path=finding.path,
                       line=finding.line, severity=finding.severity)
    if report.status != 'pass':
        return report
    if tips:
        try:
            require_visible_index(repo)
        except CommandError as exc:
            report.add('hidden-worktree', str(exc))
            return report
    if tips and config.require_tests:
        if tips != {head}:
            report.add('untested-tip', 'Check out the pushed commit before running required tests.')
        elif run(['git', 'status', '--porcelain', '--untracked-files=normal'], repo):
            report.add('dirty-worktree', 'Commit or isolate working changes before testing the pushed commit.')
        else:
            before = scan(repo, 'worktree', patterns=config.aggressiveness == 'strict')
            report.snapshot = before.snapshot
            if before.status != 'pass':
                report.status, report.findings = before.status, before.findings
                return report
            index = run(['git', 'ls-files', '--stage', '-z'], repo)
            tests = command_check(repo, 'test')
            for finding in tests.findings:
                report.add(finding.rule, finding.message, severity=finding.severity)
            after = scan(repo, 'worktree', patterns=config.aggressiveness == 'strict')
            current_head = run(['git', 'rev-parse', '--verify', 'HEAD'], repo).decode().strip()
            try:
                require_visible_index(repo)
            except CommandError as exc:
                report.add('test-snapshot-changed', str(exc))
            if (after.status != 'pass' or after.snapshot != before.snapshot
                    or current_head != head or run(['git', 'ls-files', '--stage', '-z'], repo) != index
                    or run(['git', 'status', '--porcelain', '--untracked-files=normal'], repo)):
                report.add('test-snapshot-changed',
                           'Tests changed source, permissions, index, or HEAD; restore the pushed snapshot and rerun.')
    return report
