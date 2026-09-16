"""Validate Git's actual ref updates, not shell-command guesses."""
import fnmatch
import re

from .checks import command_check
from .config import load
from .runtime import CommandError, Report, run
from .security import MAX_FILE_BYTES, scan_text
from .python_security import inspect_python

OID = re.compile(r'[0-9a-f]{40}(?:[0-9a-f]{24})?')
MAX_COMMITS = 2000


def scan_revision(repo, revision, patterns=False):
    report = Report('history-security', snapshot=revision)
    message = run(['git', 'log', '-1', '--format=%B', revision], repo, limit=64_000)
    scan_text(report, '(commit message)', message.decode('latin-1'))
    records = run(['git', 'ls-tree', '-rz', '--full-tree', revision], repo).split(b'\0')
    for record in filter(None, records):
        metadata, raw_path = record.split(b'\t', 1)
        mode, kind, oid = metadata.split()
        path = raw_path.decode('utf-8', errors='surrogateescape')
        if kind != b'blob':
            report.add('submodule-unscanned', 'Submodule content requires its own audit.',
                       path=path, severity='warning')
            continue
        try:
            if int(run(['git', 'cat-file', '-s', oid.decode()], repo)) > MAX_FILE_BYTES:
                raise CommandError('File exceeds scan size limit')
            content = run(['git', 'cat-file', 'blob', oid.decode()], repo, limit=MAX_FILE_BYTES)
            scan_text(report, path, content.decode('latin-1'))
            if patterns:
                inspect_python(report, path, content)
        except CommandError as exc:
            report.add('scan-incomplete', str(exc), path=path, severity='warning')
    return report


def pre_push(repo, updates):
    report = Report('pre-push')
    config = load(repo)
    head = run(['git', 'rev-parse', '--verify', 'HEAD'], repo).decode().strip()
    commits = set()
    tips = set()
    for line in updates.splitlines():
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
        try:
            tip = run(['git', 'rev-parse', '--verify', local_oid + '^{commit}'], repo).decode().strip()
            tips.add(tip)
            args = ['git', 'rev-list', f'--max-count={MAX_COMMITS + 1}', tip]
            if set(remote_oid) != {'0'}:
                try:
                    old = run(['git', 'rev-parse', '--verify', remote_oid + '^{commit}'], repo).decode().strip()
                except CommandError:
                    old = None  # Missing remote history: conservatively scan all local history.
                if old:
                    args += ['^' + old]
            outgoing = run(args, repo).decode().splitlines()
            if len(outgoing) > MAX_COMMITS:
                report.add('history-limit', 'Push exceeds the 2000-commit audit limit; audit a smaller range.')
            else:
                commits.update(outgoing)
        except CommandError as exc:
            report.add('history-unavailable', str(exc))
    if report.status != 'pass':
        return report
    for commit in sorted(commits):
        result = scan_revision(repo, commit, patterns=config.aggressiveness == 'strict' and commit in tips)
        for finding in result.findings:
            report.add(finding.rule, f'{commit[:12]}: {finding.message}', path=finding.path,
                       line=finding.line, severity=finding.severity)
    if report.status != 'pass':
        return report
    if tips and config.require_tests:
        if tips != {head}:
            report.add('untested-tip', 'Check out the pushed commit before running required tests.')
        elif run(['git', 'status', '--porcelain', '--untracked-files=normal'], repo):
            report.add('dirty-worktree', 'Commit or isolate working changes before testing the pushed commit.')
        else:
            tests = command_check(repo, 'test')
            for finding in tests.findings:
                report.add(finding.rule, finding.message, severity=finding.severity)
            current_head = run(['git', 'rev-parse', '--verify', 'HEAD'], repo).decode().strip()
            if current_head != head or run(['git', 'status', '--porcelain', '--untracked-files=normal'], repo):
                report.add('test-snapshot-changed',
                           'Tests changed HEAD or working files; restore a clean pushed snapshot and rerun.')
    return report
