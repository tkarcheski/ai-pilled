"""Read-only, deterministic follow-ups from configuration and historical evidence."""
from pathlib import Path
import re

from .config import load
from .credentials import redact_data
from .reporting import entries, latest_entries
from .runtime import CommandError

GATES = ('test', 'lint', 'typecheck', 'deadcode', 'coverage')
RECHECKS = {
    'security': ['scan', '--scope', 'worktree', '--patterns'],
    'staged-review': ['review-checks'],
    'quality': ['quality'],
    'pr-readiness': ['ready'],
    'full-audit': ['full-audit'],
    'dependency-vulnerabilities': ['dependency-audit'],
    **{name: ['check', name] for name in GATES},
}


def latest_checks(records):
    latest = {name: entry['report'] for name, entry in latest_entries(records).items()}
    if any(not re.fullmatch(r'[a-z][a-z0-9-]{0,79}', name) for name in latest):
        raise CommandError('Cannot suggest from an invalid check identity')
    return latest


def suggest(repo, limit=5):
    if type(limit) is not int or not 1 <= limit <= 20:
        raise CommandError('Suggestion limit must be between 1 and 20')
    repo = Path(repo)
    config = load(repo)
    latest = latest_checks(entries(repo))
    suggestions = []

    def add(identifier, priority, kind, reason, next_step, arguments=None):
        suggestions.append({'id': identifier, 'priority': priority, 'kind': kind,
                            'reason': reason, 'next': next_step,
                            'command': ['python', '-m', 'ai_pilled', '--repo', str(repo.resolve()), *arguments] if arguments else None})

    for name, report in latest.items():
        if report['status'] == 'pass':
            continue
        arguments = RECHECKS.get(name, ['summary'])
        if name == 'python-dependency-vulnerabilities' and config.python_requirements:
            arguments = ['python-audit', '--pip-audit', config.python_audit_executable]
            for path in config.python_requirements:
                arguments += ['--requirements', path]
        if arguments:
            aggregate = name in ('quality', 'staged-review', 'pr-readiness', 'full-audit')
            add('recheck-' + name, 2 if aggregate else 0, 'recorded-result',
                f'The latest recorded {name} result is {report["status"]}; it may be stale.',
                ('Inspect the findings, fix their cause, and rerun against the current files.'
                 if arguments != ['summary'] else
                 'Inspect recorded findings and select the matching check; do not replay external actions automatically.'), arguments)

    for name in GATES:
        if name not in config.commands:
            add('configure-' + name, 1, 'feature-configuration',
                f'commands.{name} is absent; comprehensive review cannot complete this gate.',
                f'Configure a trusted {name} command, then verify it.', ['check', name])
    if not config.require_tests:
        add('require-push-tests', 2, 'feature-configuration',
            'Required push tests are disabled.',
            'Review the policy and enable require_tests if pushes should require test evidence.')
    if not config.protected_branches:
        add('protect-destinations', 2, 'feature-configuration',
            'No destination branch patterns are protected.',
            'Select the intended protected branches; configure protected_branches explicitly.')
    if not config.review_checks_on_commit:
        add('enable-staged-review', 2, 'feature-configuration',
            'Comprehensive staged checks are not enabled on commits.',
            'Configure the missing gates first, then enable review_checks_on_commit.', ['review-checks'])
    if config.aggressiveness != 'strict':
        add('strict-quality-profile', 3, 'feature-configuration',
            'The strict quality profile is not selected for explicit quality and post-tool checks.',
            'Configure its required gates before selecting aggressiveness: strict.', ['quality'])
    pins = [name for name in ('requirements.txt', 'requirements-dev.txt') if (repo / name).is_file()]
    if pins and not config.python_requirements:
        add('configure-python-audit', 2, 'feature-configuration',
            'Python requirements exist but no explicit Python audit scope is configured.',
            'Export complete exact pins, install a trusted pip-audit, and select python_requirements.')
    if 'benchmark' not in config.commands:
        add('configure-performance-baseline', 3, 'feature-configuration',
            'No repeatable performance command is configured.',
            'Select commands.benchmark and review repeated timings before explicitly saving a baseline.')
    if any(name not in config.commands for name in ('simplify', 'repair')):
        add('configure-disposable-refactor', 3, 'feature-configuration',
            'The disposable simplify/repair workflow is not fully configured.',
            'Select trusted simplify and repair commands; inspect the verified patch before applying it.')
    if not suggestions:
        add('verify-current-index', 4, 'verification',
            'No supported configuration gaps or unresolved recorded checks were identified.',
            'Stage the intended change and validate it; historical passes do not certify current files.',
            ['review-checks'])
    suggestions.sort(key=lambda item: (item['priority'], item['id']))
    return redact_data({'evidence': 'Configuration and recorded outcomes only; no checks or suggested actions were executed.',
                        'suggestions': suggestions[:limit], 'omitted': max(0, len(suggestions) - limit)})
