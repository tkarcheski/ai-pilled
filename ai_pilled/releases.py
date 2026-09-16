"""Deterministic changelogs and semantic-version proposals from committed history."""
from dataclasses import dataclass
import html
import re

from .runtime import CommandError, Report, run
from .security import scan_text

VERSION = re.compile(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)')
SUBJECT = re.compile(r'(?P<type>[a-z]+)(?:\((?P<scope>[^()\r\n]+)\))?(?P<breaking>!)?: (?P<summary>\S.*)')
GROUPS = {'feat': 'Features', 'fix': 'Fixes', 'perf': 'Performance',
          'refactor': 'Refactoring', 'docs': 'Documentation',
          'test': 'Tests', 'build': 'Maintenance', 'ci': 'Maintenance', 'chore': 'Maintenance'}


@dataclass
class ReleaseReport(Report):
    current_version: str = ''
    next_version: str = ''
    bump: str = 'none'
    changelog: str = ''


def markdown_text(value):
    value = html.escape(value, quote=False)
    value = re.sub(r'([\\*_\[\]{}()#+!|])', r'\\\1', value)
    return value.replace(chr(96), '\\' + chr(96))


def commits(repo, since=None):
    head = run(['git', 'rev-parse', '--verify', 'HEAD^{commit}'], repo).decode().strip()
    target = head
    if since is not None:
        base = run(['git', 'rev-parse', '--verify', '--end-of-options', since + '^{commit}'], repo).decode().strip()
        try:
            run(['git', 'merge-base', '--is-ancestor', base, head], repo)
        except CommandError as exc:
            raise CommandError('Changelog base must be an ancestor of HEAD') from exc
        target = base + '..' + head
    output = run(['git', 'log', '--reverse', '--max-count=1001',
                  '--format=%H%x00%B%x00', target, '--'], repo)
    fields = output.decode('utf-8', errors='replace').split('\0')
    result = []
    for index in range(0, len(fields) - 1, 2):
        oid, message = fields[index].strip(), fields[index + 1]
        if not re.fullmatch(r'[a-f0-9]{40}(?:[a-f0-9]{24})?', oid):
            raise CommandError('Cannot parse bounded commit history')
        credentials = Report('commit-credentials')
        scan_text(credentials, '(commit message)', message)
        if credentials.status != 'pass':
            raise CommandError(f'Commit {oid[:12]} contains potential credentials; resolve before generating notes')
        subject, _, body = message.partition('\n')
        match = SUBJECT.fullmatch(subject)
        kind = match.group('type') if match else 'other'
        breaking = bool(match and match.group('breaking')) or bool(re.search(
            r'^BREAKING[ -]CHANGE:\s*\S', body, re.MULTILINE))
        result.append({'oid': oid, 'subject': subject, 'type': kind, 'breaking': breaking})
    if len(result) > 1000:
        raise CommandError('Changelog exceeds the 1000-commit limit; select a narrower base')
    return head, result


def release_plan(repo, current, since=None):
    report = ReleaseReport('release-plan', current_version=current)
    try:
        if not VERSION.fullmatch(current):
            raise CommandError('Current version must be a stable MAJOR.MINOR.PATCH version')
        head, changes = commits(repo, since)
        report.snapshot = head
        bump = 'none'
        if any(change['breaking'] for change in changes):
            bump = 'major'
        elif any(change['type'] == 'feat' for change in changes):
            bump = 'minor'
        elif any(change['type'] in ('fix', 'perf') for change in changes):
            bump = 'patch'
        major, minor, patch = map(int, current.split('.'))
        if bump == 'major':
            major, minor, patch = major + 1, 0, 0
        elif bump == 'minor':
            minor, patch = minor + 1, 0
        elif bump == 'patch':
            patch += 1
        report.next_version = f'{major}.{minor}.{patch}'
        report.bump = bump
        groups: dict[str, list[str]] = {}
        for change in changes:
            label = 'Breaking changes' if change['breaking'] else GROUPS.get(change['type'], 'Other')
            groups.setdefault(label, []).append(
                f'- {markdown_text(change["subject"])} ({change["oid"][:12]})')
        title = report.next_version if bump != 'none' else 'Unreleased'
        lines = [f'## {title}', '']
        for label, items in groups.items():
            lines.extend([f'### {label}', '', *items, ''])
        if not changes:
            lines.extend(['No commits in the selected range.', ''])
        report.changelog = '\n'.join(lines)
        report.metrics = {'commits': len(changes)}
    except (CommandError, ValueError) as exc:
        report.add('release-plan-unavailable', str(exc), severity='warning')
    return report
