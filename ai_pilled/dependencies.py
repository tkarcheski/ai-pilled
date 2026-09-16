"""Structured npm lockfile vulnerability audits; never installs or applies fixes."""
import hashlib
import json
import os
from pathlib import Path
import re

from .config import load
from .runtime import CommandError, Report, run
from .state import record

SEVERITIES = ('info', 'low', 'moderate', 'high', 'critical')


def snapshot(repo):
    digest = hashlib.sha256()
    found_lock = False
    for name in ('package.json', 'package-lock.json', 'npm-shrinkwrap.json'):
        path = repo / name
        if path.is_symlink():
            raise CommandError('Dependency inputs must be regular files, not symlinks')
        if not path.exists():
            continue
        if not path.is_file() or path.stat().st_size > 2_000_000:
            raise CommandError('Dependency input is not a bounded regular file')
        content = path.read_bytes()
        data = json.loads(content)
        if not isinstance(data, dict):
            raise CommandError('Dependency input must be a JSON object')
        if name != 'package.json':
            found_lock = True
        digest.update(name.encode() + b'\0' + content + b'\0')
    if not found_lock or not (repo / 'package.json').is_file():
        raise CommandError('npm audit requires package.json and a package-lock.json or npm-shrinkwrap.json')
    return digest.hexdigest()


def parse_npm(data):
    if not isinstance(data, dict) or data.get('auditReportVersion') != 2 or 'error' in data:
        raise CommandError('npm returned an unsupported or failed audit report')
    vulnerabilities = data.get('vulnerabilities')
    metadata = data.get('metadata')
    if not isinstance(vulnerabilities, dict) or not isinstance(metadata, dict):
        raise CommandError('npm returned an incomplete audit report')
    counts = metadata.get('vulnerabilities')
    if not isinstance(counts, dict) or any(type(counts.get(k)) is not int or counts[k] < 0
                                          for k in (*SEVERITIES, 'total')):
        raise CommandError('npm returned invalid vulnerability counts')
    if counts['total'] != len(vulnerabilities) or sum(counts[k] for k in SEVERITIES) != counts['total']:
        raise CommandError('npm vulnerability counts do not match its findings')
    findings = []
    observed = dict.fromkeys(SEVERITIES, 0)
    for name, item in vulnerabilities.items():
        if not re.fullmatch(r'(?:@[a-z0-9._-]+/)?[a-z0-9._-]{1,214}', name):
            raise CommandError('npm returned an invalid package name')
        if not isinstance(item, dict) or item.get('severity') not in SEVERITIES:
            raise CommandError('npm returned an invalid vulnerability')
        severity = item['severity']
        observed[severity] += 1
        fix = item.get('fixAvailable')
        if type(fix) is not bool and not isinstance(fix, dict):
            raise CommandError('npm omitted vulnerability remediation information')
        remedy = 'A fix is available; review the version change.' if fix else 'No automatic fix is reported.'
        findings.append((name, f'{name}: {severity} vulnerability. {remedy}'))
    if any(observed[k] != counts[k] for k in SEVERITIES):
        raise CommandError('npm severity counts do not match its findings')
    return findings


def audit(repo, executable='npm'):
    repo = Path(repo).resolve()
    report = Report('dependency-vulnerabilities')
    try:
        before = snapshot(repo)
        report.snapshot = before
        env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
        output = run([executable, 'audit', '--json', '--package-lock-only',
                      '--ignore-scripts', '--include=dev', '--include=optional',
                      '--include=peer', '--audit-level=low'],
                     repo, env=env, timeout=load(repo).timeout, acceptable_codes=(0, 1))
        findings = parse_npm(json.loads(output))
        if snapshot(repo) != before:
            raise CommandError('Dependency inputs changed during audit; rerun it')
        for name, message in findings:
            report.add('dependency-vulnerability', message, path=name)
    except (CommandError, ValueError, OSError) as exc:
        report.add('dependency-audit-unavailable',
                   str(exc) if isinstance(exc, CommandError) else 'Cannot read a valid dependency audit',
                   severity='warning')
    record(repo, report, 'dependency-audit')
    return report
