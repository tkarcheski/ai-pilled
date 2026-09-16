"""Explicit GitHub auto-merge requests pinned to a reviewed PR head."""
from dataclasses import dataclass
from .json_data import loads
import os
import re

from .runtime import CommandError, Report, run

FIELDS = 'number,state,isDraft,baseRefName,headRefOid,reviewDecision,mergeable,autoMergeRequest'


@dataclass
class MergeReport(Report):
    action: str = 'not-requested'
    target: str = ''


def auto_merge(repo, github_repo, number, base, expected_head, enable=False, executable='gh'):
    report = MergeReport('auto-merge')
    try:
        if (not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}', github_repo)
                or github_repo.split('/')[-1] in ('.', '..') or type(number) is not int or number < 1):
            raise CommandError('Select an explicit GitHub owner/repository and positive PR number')
        if not base or len(base) > 200 or any(ord(c) < 32 for c in base):
            raise CommandError('Select an explicit expected base branch')
        if not re.fullmatch(r'[a-f0-9]{40}(?:[a-f0-9]{24})?', expected_head):
            raise CommandError('Supply the full expected PR head commit SHA')
        report.target = f'{github_repo}#{number}'
        report.snapshot = expected_head
        env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
        env.update({'GH_HOST': 'github.com', 'GH_PROMPT_DISABLED': '1', 'GH_NO_UPDATE_NOTIFIER': '1'})
        selection = [str(number), '--repo', 'github.com/' + github_repo]
        def view():
            return loads(run([executable, 'pr', 'view', *selection, '--json', FIELDS],
                                  repo, env=env, timeout=30, limit=100_000))
        def validate(data):
            if not isinstance(data, dict) or data.get('number') != number:
                raise CommandError('Cannot verify the selected pull request')
            if data.get('headRefOid') != expected_head or data.get('baseRefName') != base:
                raise CommandError('PR head or base no longer matches the explicit selection')
            if data.get('state') != 'OPEN' or data.get('isDraft') is not False:
                raise CommandError('Auto-merge requires an open, non-draft pull request')
            if data.get('reviewDecision') != 'APPROVED' or data.get('mergeable') != 'MERGEABLE':
                raise CommandError('PR must be approved and confirmed mergeable before enabling auto-merge')
        validate(view())
        checks = loads(run([executable, 'pr', 'checks', *selection, '--required', '--json', 'bucket'],
                                repo, env=env, timeout=30, limit=100_000, acceptable_codes=(0, 1, 8)))
        if not isinstance(checks, list) or not checks or any(
                not isinstance(check, dict) or check.get('bucket') not in ('pass', 'pending') for check in checks):
            raise CommandError('Required checks must exist and be passing or pending; failures or unknown states block')
        report.metrics = {'required_checks': len(checks),
                          'pending_checks': sum(check['bucket'] == 'pending' for check in checks)}
        report.action = 'preview'
        if enable:
            validate(view())
            # --auto may merge immediately when requirements already pass. No admin bypass.
            report.action = 'unconfirmed'
            run([executable, 'pr', 'merge', *selection, '--auto', '--squash',
                 '--match-head-commit', expected_head], repo, env=env, timeout=30)
            after = view()
            if (not isinstance(after, dict) or after.get('number') != number
                    or after.get('headRefOid') != expected_head or after.get('baseRefName') != base):
                raise CommandError('Merge outcome differs from selected PR; inspect GitHub before retrying')
            if after.get('state') == 'MERGED':
                report.action = 'merged'
            elif after.get('state') == 'OPEN' and isinstance(after.get('autoMergeRequest'), dict):
                report.action = 'enabled'
            else:
                raise CommandError('Auto-merge was not confirmed; inspect GitHub before retrying')
    except (CommandError, ValueError, OSError) as exc:
        report.add('merge-unavailable', str(exc) if isinstance(exc, CommandError)
                   else 'Cannot read a valid GitHub merge result; inspect GitHub before retrying', severity='warning')
    return report
