"""Installed npm tree health and explicit lockfile license-expression policy."""
import json
import os
from pathlib import Path
import re

from .config import load
from .dependencies import snapshot
from .runtime import CommandError, Report, run
from .state import record

PACKAGE = re.compile(r'(?:@[a-z0-9._-]+/)?[a-z0-9._-]{1,214}')
VERSION = re.compile(r'\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?')


def health(repo, executable='npm'):
    repo = Path(repo).resolve()
    report = Report('dependency-health')
    try:
        before = snapshot(repo)
        report.snapshot = before
        config = load(repo)
        env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
        tree = json.loads(run([executable, 'ls', '--all', '--json', '--ignore-scripts',
                               '--include=dev', '--include=optional', '--include=peer'],
                              repo, env=env, timeout=config.timeout, acceptable_codes=(0, 1)))
        if not isinstance(tree, dict) or not isinstance(tree.get('dependencies', {}), dict):
            raise CommandError('npm returned an invalid installed dependency tree')
        if 'name' not in tree and 'dependencies' not in tree:
            raise CommandError('npm returned no installed dependency tree')
        problems = tree.get('problems', [])
        if not isinstance(problems, list) or any(not isinstance(p, str) for p in problems):
            raise CommandError('npm returned invalid dependency problems')
        error = tree.get('error')
        if error is not None and (not isinstance(error, dict) or error.get('code') != 'ELSPROBLEMS' or not problems):
            raise CommandError('npm could not inspect the installed dependency tree')
        if problems:
            report.add('dependency-tree-problems',
                       f'npm reports {len(problems)} invalid, missing, or extraneous dependency entries; inspect npm ls.')
        outdated = json.loads(run([executable, 'outdated', '--all', '--json', '--ignore-scripts'],
                                  repo, env=env, timeout=config.timeout, acceptable_codes=(0, 1)))
        if not isinstance(outdated, dict) or 'error' in outdated:
            raise CommandError('npm could not inspect available dependency versions')
        for name, item in outdated.items():
            if not PACKAGE.fullmatch(name) or not isinstance(item, dict):
                raise CommandError('npm returned an invalid outdated package')
            current, wanted, latest = (item.get(k) for k in ('current', 'wanted', 'latest'))
            if any(not isinstance(v, str) or not VERSION.fullmatch(v) for v in (current, wanted, latest)):
                report.add('version-unavailable', 'Installed and available versions could not all be compared.',
                           path=name, severity='warning')
                continue
            report.add('dependency-outdated', f'{name}: installed {current}, wanted {wanted}, latest tag {latest}.',
                       path=name, severity='info')
        report.metrics = {'tree_problems': len(problems), 'outdated_packages': len(outdated)}
        if snapshot(repo) != before:
            raise CommandError('Dependency inputs changed during health checks; rerun them')
    except (CommandError, ValueError, OSError) as exc:
        report.add('dependency-health-unavailable', str(exc) if isinstance(exc, CommandError)
                   else 'Cannot read a valid dependency health report', severity='warning')
    record(repo, report, 'dependency-health')
    return report


def licenses(repo, allowed):
    repo = Path(repo).resolve()
    report = Report('dependency-license-policy')
    try:
        if not allowed or any(not isinstance(value, str) or not value or len(value) > 200 for value in allowed):
            raise CommandError('Supply at least one explicitly allowed license expression')
        before = snapshot(repo)
        report.snapshot = before
        path = repo / ('npm-shrinkwrap.json' if (repo / 'npm-shrinkwrap.json').exists() else 'package-lock.json')
        data = json.loads(path.read_text())
        packages = data.get('packages')
        if data.get('lockfileVersion') not in (2, 3) or not isinstance(packages, dict):
            raise CommandError('License checks require npm lockfile version 2 or 3 package metadata')
        checked = 0
        for location, package in packages.items():
            if location == '':
                continue
            if not isinstance(package, dict):
                raise CommandError('Invalid package metadata in lockfile')
            checked += 1
            license_expression = package.get('license')
            if package.get('link') or not isinstance(license_expression, str) or not license_expression:
                report.add('license-unknown', 'Package has no usable license metadata; review its license separately.',
                           path=location, severity='warning')
            elif license_expression not in allowed:
                report.add('license-not-allowed', 'Declared license expression is absent from the supplied allowlist.',
                           path=location)
        report.metrics = {'packages_checked': checked}
        if snapshot(repo) != before:
            raise CommandError('Dependency inputs changed during license checks; rerun them')
    except (CommandError, ValueError, OSError) as exc:
        report.add('license-check-unavailable', str(exc) if isinstance(exc, CommandError)
                   else 'Cannot read valid dependency license metadata', severity='warning')
    record(repo, report, 'license-policy')
    return report
