"""Deterministic changelogs and semantic-version proposals from committed history."""
from dataclasses import dataclass, field
import html
import re

from .file_io import read_regular
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
    files: list[str] = field(default_factory=list)


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
                  '--format=%H%x00%P%x00%B%x00', target, '--'], repo)
    fields = output.decode('utf-8', errors='replace').split('\0')
    result = []
    for index in range(0, len(fields) - 1, 3):
        oid, parents, message = fields[index].strip(), fields[index + 1].split(), fields[index + 2]
        if not re.fullmatch(r'[a-f0-9]{40}(?:[a-f0-9]{24})?', oid):
            raise CommandError('Cannot parse bounded commit history')
        metadata = run(['git', 'cat-file', 'commit', oid], repo, limit=128_000)
        headers, separator, _ = metadata.partition(b'\n\n')
        raw_parents = [line[7:].decode('ascii', errors='replace')
                       for line in headers.splitlines() if line.startswith(b'parent ')]
        if not separator or sorted(parents) != sorted(raw_parents):
            raise CommandError('Release ancestry is truncated; obtain complete history for the selected range')
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

def prepare_release(repo, current, since=None):
    from pathlib import Path
    from .metrics import local_path
    from .pipeline import quality
    from .state import atomic_text

    repo = Path(run(['git', 'rev-parse', '--show-toplevel'], repo).decode().strip())
    report = release_plan(repo, current, since)
    report.check = 'release-prepare'
    if report.status != 'pass':
        return report
    if report.bump == 'none':
        report.add('no-release-change', 'The selected commits do not require a version bump.', severity='warning')
        return report
    try:
        def metadata(path):
            try:
                return read_regular(path, 2_000_000).decode('utf-8')
            except FileNotFoundError:
                return None
        paths = [local_path(repo, 'VERSION'), local_path(repo, 'CHANGELOG.md')]
        originals = {}
        modes = {}
        for path in paths:
            originals[path] = metadata(path)
            modes[path] = path.stat().st_mode & 0o777 if path.exists() else 0o644
        original_version = originals[paths[0]]
        if original_version is not None and original_version.strip() != current:
            raise CommandError('VERSION does not match the supplied current version')
        old_changelog = originals[paths[1]] or ''
        if re.search(r'^## ' + re.escape(report.next_version) + r'(?:\s|$)', old_changelog, re.MULTILINE):
            raise CommandError('CHANGELOG already contains the proposed version')
        readiness = quality(repo, ready=True)
        if readiness.status != 'pass':
            for finding in readiness.findings:
                report.add('readiness:' + finding.rule, finding.message, path=finding.path,
                           line=finding.line, severity=finding.severity)
            return report
        if run(['git', 'rev-parse', 'HEAD'], repo).decode().strip() != report.snapshot:
            raise CommandError('HEAD changed after release planning; rerun the preparation')
        for path, original in originals.items():
            if metadata(path) != original:
                raise CommandError('Release metadata changed during checks; rerun the preparation')
        if old_changelog.startswith('# Changelog\n'):
            old_changelog = old_changelog[len('# Changelog\n'):].lstrip('\n')
        contents = [report.next_version + '\n',
                    '# Changelog\n\n' + report.changelog.rstrip() + '\n\n' + old_changelog]
        written = []
        try:
            for path, content in zip(paths, contents, strict=True):
                atomic_text(path, content, modes[path])
                written.append(path)
        except OSError:
            for path in reversed(written):
                if originals[path] is None:
                    path.unlink()
                else:
                    atomic_text(path, originals[path], modes[path])
            raise
        report.files = [path.name for path in paths]
    except (CommandError, OSError, UnicodeError) as exc:
        report.add('release-prepare-unavailable', str(exc) if isinstance(exc, CommandError)
                   else 'Cannot prepare release metadata files', severity='warning')
    return report
