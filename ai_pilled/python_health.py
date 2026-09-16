"""Inspect a selected Python environment without installing or importing its packages."""
import hashlib
import json
import os
from pathlib import Path
import re
import time

from .config import load
from .json_data import loads
from .python_dependencies import NAME, VERSION, canonical
from .runtime import CommandError, CommandFailed, CommandUnavailable, Report, run
from .security import scan_text
from .state import record


def pip_command(repo, executable, arguments, timeout=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith(('GIT_', 'PIP_', 'PYTHON'))}
    env.update(PIP_CONFIG_FILE=os.devnull, PIP_NO_INPUT='1', PIP_DISABLE_PIP_VERSION_CHECK='1',
               PYTHONDONTWRITEBYTECODE='1')
    return run([executable, '-I', '-m', 'pip', *arguments], repo,
               env=env, timeout=min(load(repo).timeout, timeout) if timeout is not None else load(repo).timeout)


def installed(repo, executable):
    data = loads(pip_command(repo, executable, ['inspect']))
    if (not isinstance(data, dict) or data.get('version') != '1'
            or not isinstance(data.get('installed'), list) or not isinstance(data.get('environment'), dict)):
        raise CommandError('Expected a supported pip inspect environment report')
    packages: dict[str, dict] = {}
    for item in data['installed']:
        metadata = item.get('metadata') if isinstance(item, dict) else None
        if (not isinstance(metadata, dict) or not isinstance(metadata.get('name'), str)
                or not re.fullmatch(NAME, metadata['name']) or not isinstance(metadata.get('version'), str)
                or not re.fullmatch(VERSION, metadata['version'])):
            raise CommandError('Installed Python package metadata is incomplete or invalid')
        name = canonical(metadata['name'])
        if name in packages:
            raise CommandError('Duplicate installed Python package identities require review')
        checked = Report('package-metadata-security')
        scan_text(checked, '(package)', name + '==' + metadata['version'])
        if checked.status != 'pass':
            raise CommandError('Installed package identity contains potential credentials')
        packages[name] = {'metadata': metadata, 'direct_url': item.get('direct_url')}
    fingerprint = hashlib.sha256(json.dumps({'packages': packages, 'environment': data['environment']},
                                           sort_keys=True).encode()).hexdigest()
    return fingerprint, packages


def health_python(repo, executable, outdated=False):
    repo = Path(repo).resolve()
    report = Report('python-dependency-health')
    try:
        before, packages = installed(repo, executable)
        report.snapshot = before
        try:
            pip_command(repo, executable, ['check'])
        except CommandFailed as exc:
            if exc.exit_code != 1:
                raise
            report.add('python-dependency-conflicts', 'pip check failed; inspect the selected environment for missing or incompatible dependencies.')
        findings = []
        if outdated:
            deadline = time.monotonic() + load(repo).timeout
            for name, package in packages.items():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise CommandUnavailable('Python version queries exceeded the configured timeout')
                item = loads(pip_command(repo, executable, ['index', 'versions', name, '--json',
                             '--index-url', 'https://pypi.org/simple', '--retries', '0', '--timeout', '10'],
                             timeout=remaining))
                versions = item.get('versions') if isinstance(item, dict) else None
                current = package['metadata']['version']
                if (not isinstance(item, dict) or not isinstance(item.get('name'), str)
                        or canonical(item['name']) != name or item.get('installed_version') != current
                        or not isinstance(versions, list) or not versions
                        or any(not isinstance(v, str) or not re.fullmatch(VERSION, v) for v in versions)
                        or item.get('latest') != versions[0]):
                    raise CommandError('Package index evidence differs from the inspected environment')
                if current not in versions:
                    report.add('python-version-unavailable',
                               'Installed version is absent from compatible public releases; compare it manually.',
                               path=name, severity='warning')
                elif current != item['latest']:
                    findings.append((name, f'{name}: installed {current}, latest available {item["latest"]}.'))
        if installed(repo, executable)[0] != before:
            raise CommandError('Python environment changed during health checks; rerun them')
        for name, message in findings:
            report.add('python-dependency-outdated', message, path=name, severity='info')
        report.metrics = {'packages_checked': len(packages), 'outdated_checked': int(outdated),
                          'outdated_packages': len(findings), 'version_queries': len(packages) if outdated else 0}
    except (CommandError, ValueError, OSError) as exc:
        report.add('python-health-unavailable', str(exc) if isinstance(exc, CommandError)
                   else 'Cannot read valid Python environment evidence', severity='warning')
    record(repo, report, 'python-dependency-health')
    return report


def licenses_python(repo, executable, allowed):
    repo = Path(repo).resolve()
    report = Report('python-dependency-license-policy')
    try:
        if not allowed or any(not isinstance(value, str) or not value or len(value) > 200 for value in allowed):
            raise CommandError('Supply explicitly allowed license expressions')
        before, packages = installed(repo, executable)
        report.snapshot = before
        for name, item in packages.items():
            metadata = item['metadata']
            expression = metadata.get('license_expression') or metadata.get('license')
            if not isinstance(expression, str) or not expression.strip() or len(expression) > 200 or expression == 'UNKNOWN':
                report.add('python-license-unknown', 'Package has no usable license expression; review its license separately.',
                           path=name, severity='warning')
            elif expression not in allowed:
                report.add('python-license-not-allowed', 'Declared license expression is absent from the supplied allowlist.', path=name)
        if installed(repo, executable)[0] != before:
            raise CommandError('Python environment changed during license checks; rerun them')
        report.metrics = {'packages_checked': len(packages)}
    except (CommandError, ValueError, OSError) as exc:
        report.add('python-license-check-unavailable', str(exc) if isinstance(exc, CommandError)
                   else 'Cannot read valid Python license evidence', severity='warning')
    record(repo, report, 'python-license-policy')
    return report
