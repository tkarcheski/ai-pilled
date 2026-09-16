"""Explicit GitHub release publication from verified, already-pushed tags."""
from dataclasses import dataclass
from .json_data import loads
import os
from pathlib import Path
import re

from .config import ConfigError
from .metrics import local_path
from .pipeline import quality
from .releases import VERSION
from .runtime import CommandError, Report, run
from .security import scan_text


@dataclass
class PublishReport(Report):
    action: str = 'not-published'
    target: str = ''
    notes: str = ''


def publish_release(repo, github_repo, tag, expected_head, publish=False, executable='gh'):
    report = PublishReport('release-publish')
    try:
        if (not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}', github_repo)
                or github_repo.split('/')[-1] in ('.', '..')):
            raise CommandError('Select an explicit GitHub owner/repository')
        version = tag.removeprefix('v')
        if not tag.startswith('v') or not VERSION.fullmatch(version):
            raise CommandError('Use a stable vMAJOR.MINOR.PATCH tag')
        root = Path(run(['git', 'rev-parse', '--show-toplevel'], repo).decode().strip())
        head = run(['git', 'rev-parse', '--verify', 'HEAD'], root).decode().strip()
        if expected_head != head:
            raise CommandError('Expected HEAD must exactly match the release commit SHA')
        def unchanged():
            if run(['git', 'rev-parse', 'HEAD'], root).decode().strip() != head or run(
                    ['git', 'status', '--porcelain', '--untracked-files=normal'], root):
                raise CommandError('Release requires an unchanged clean committed checkout')
            if run(['git', 'rev-parse', '--verify', 'refs/tags/' + tag + '^{commit}'], root).decode().strip() != head:
                raise CommandError('Local release tag must point to the selected commit')
        unchanged()
        run(['git', 'ls-files', '--error-unmatch', '--', 'VERSION', 'CHANGELOG.md'], root)
        version_path, changelog_path = local_path(root, 'VERSION'), local_path(root, 'CHANGELOG.md')
        if version_path.stat().st_size > 100 or changelog_path.stat().st_size > 2_000_000:
            raise CommandError('Release metadata exceeds size limits')
        if version_path.read_text().strip() != version:
            raise CommandError('VERSION must match the selected tag')
        changelog = changelog_path.read_text()
        headings = list(re.finditer(r'^## ([^\n]+)\n', changelog, re.MULTILINE))
        matching = [i for i, heading in enumerate(headings) if heading.group(1).strip() == version]
        if len(matching) != 1:
            raise CommandError('CHANGELOG must have one exact heading for the selected version')
        index = matching[0]
        start = headings[index].end()
        end = headings[index + 1].start() if index + 1 < len(headings) else len(changelog)
        notes = changelog[start:end].strip()
        if not notes or len(notes.encode()) > 100_000:
            raise CommandError('Release notes must be nonempty and bounded')
        scanned = Report('release-notes')
        scan_text(scanned, 'CHANGELOG.md', notes)
        if scanned.status != 'pass':
            raise CommandError('Resolve credential findings before previewing or publishing notes')
        checked = quality(root)
        if checked.status != 'pass':
            report.status, report.findings = checked.status, checked.findings
            return report
        unchanged()
        env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
        env.update({'GH_HOST': 'github.com', 'GH_PROMPT_DISABLED': '1', 'GH_NO_UPDATE_NOTIFIER': '1'})
        def remote_tag():
            value = run([executable, 'api', '--hostname', 'github.com',
                         f'repos/{github_repo}/commits/{tag}', '--jq', '.sha'],
                        root, env=env, timeout=30, limit=1000).decode().strip()
            if value != head:
                raise CommandError('Remote release tag must point to the selected commit')
        remote_tag()
        report.snapshot, report.target, report.notes = head, github_repo + '@' + tag, notes
        report.action = 'preview'
        if publish:
            unchanged()
            remote_tag()
            report.action = 'unconfirmed'
            run([executable, 'release', 'create', tag, '--repo', 'github.com/' + github_repo,
                 '--verify-tag', '--target', head, '--title', tag, '--notes-file', '-'],
                root, env=env, timeout=30, input_data=notes.encode())
            data = loads(run([executable, 'release', 'view', tag, '--repo', 'github.com/' + github_repo,
                                   '--json', 'tagName,isDraft,isPrerelease,body,publishedAt'],
                                  root, env=env, timeout=30, limit=150_000))
            remote_tag()
            if (not isinstance(data, dict) or data.get('tagName') != tag or data.get('isDraft') is not False
                    or data.get('isPrerelease') is not False or not data.get('publishedAt')
                    or data.get('body', '').strip() != notes):
                raise CommandError('Published release was not confirmed; inspect GitHub before retrying')
            report.action = 'published'
    except (CommandError, ConfigError, OSError, ValueError, AttributeError) as exc:
        report.add('publish-unavailable', str(exc) if isinstance(exc, (CommandError, ConfigError))
                   else 'Cannot verify release publication; inspect GitHub before retrying', severity='warning')
    return report
