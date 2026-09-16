"""Structured npm lockfile vulnerability audits; never installs or applies fixes."""
import hashlib
from .json_data import loads
import os
from pathlib import Path
import re
import stat

from .config import load
from .runtime import CommandError, Report, run_completed
from .state import record

SEVERITIES = ('info', 'low', 'moderate', 'high', 'critical')
EVIDENCE_VERSION = 2


def read_input(path):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise CommandError('Dependency input must be a regular file')
        content = stream.read(2_000_001)
    if len(content) > 2_000_000:
        raise CommandError('Dependency input exceeds size limit')
    data = loads(content)
    if not isinstance(data, dict):
        raise CommandError('Dependency input must be a JSON object')
    return content, data


def snapshot(repo):
    digest = hashlib.sha256()
    found_lock = False
    for name in ('package.json', 'package-lock.json', 'npm-shrinkwrap.json'):
        path = repo / name
        if path.is_symlink():
            raise CommandError('Dependency inputs must be regular files, not symlinks')
        if not path.exists():
            continue
        content, _ = read_input(path)
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


def audit(repo, executable='npm', timeout=None):
    repo = Path(repo).resolve()
    report = Report('dependency-vulnerabilities')
    try:
        before = snapshot(repo)
        report.snapshot = before
        env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
        completed = run_completed([executable, 'audit', '--json', '--package-lock-only',
                      '--ignore-scripts', '--include=dev', '--include=optional',
                      '--include=peer', '--audit-level=low'],
                     repo, env=env, timeout=min(load(repo).timeout, timeout) if timeout else load(repo).timeout,
                     acceptable_codes=(0, 1))
        data = loads(completed.stdout)
        findings = parse_npm(data)
        expected_code = int(any(data['metadata']['vulnerabilities'][level] for level in SEVERITIES[1:]))
        if completed.returncode != expected_code:
            raise CommandError('npm exit status contradicts its audit-level vulnerability evidence')
        if snapshot(repo) != before:
            raise CommandError('Dependency inputs changed during audit; rerun it')
        for name, message in findings:
            report.add('dependency-vulnerability', message, path=name)
        report.metrics = {'vulnerabilities': len(findings), 'evidence_version': EVIDENCE_VERSION}
    except (CommandError, ValueError, OSError) as exc:
        report.add('dependency-audit-unavailable',
                   str(exc) if isinstance(exc, CommandError) else 'Cannot read a valid dependency audit',
                   severity='warning')
    record(repo, report, 'dependency-audit')
    return report

def audit_changed(repo):
    """Reuse only a recent complete result for the exact same dependency inputs."""
    from datetime import datetime, timezone
    from .runtime import Finding
    from .state import history

    repo = Path(repo)
    try:
        fingerprint = snapshot(repo)
        for entry in reversed(history(repo)):
            if not isinstance(entry, dict) or entry.get('event') != 'dependency-audit':
                continue
            data = entry.get('report', {})
            if not isinstance(data, dict) or data.get('snapshot') != fingerprint:
                continue
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(entry['at'])).total_seconds()
            if not 0 <= age < 3600 or data.get('status') not in ('pass', 'fail'):
                break
            metrics = data.get('metrics')
            if (not isinstance(metrics, dict) or type(metrics.get('evidence_version')) is not int
                    or metrics['evidence_version'] != EVIDENCE_VERSION):
                break
            findings = [Finding(**finding) for finding in data['findings']]
            if any(f.severity not in ('error', 'warning', 'info') or not isinstance(f.message, str)
                   for f in findings):
                break
            if ((data['status'] == 'pass' and any(f.severity != 'info' for f in findings))
                    or (data['status'] == 'fail' and not any(f.severity == 'error' for f in findings))):
                break
            cached = Report('dependency-vulnerabilities', status=data['status'],
                            findings=findings, snapshot=fingerprint, metrics=metrics)
            if snapshot(repo) == fingerprint:
                return cached, True
            break
    except (CommandError, ValueError, OSError, TypeError, KeyError):
        pass
    return audit(repo, timeout=30), False
