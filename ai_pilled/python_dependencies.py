"""Python audits of explicit pinned requirements; never installs packages."""
import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile

from .config import load
from .json_data import loads
from .metrics import local_path
from .runtime import CommandError, Report, run_completed
from .state import record
from .security import scan_text

NAME = r'[A-Za-z0-9](?:[A-Za-z0-9._-]{0,212}[A-Za-z0-9])?'
VERSION = r'[0-9][A-Za-z0-9.!+_-]{0,99}'
PIN = re.compile(r'(' + NAME + r')==(' + VERSION + r')')
HASH = re.compile(r'--hash=sha256:[a-fA-F0-9]{64}')
COMMENT = re.compile(r'(^|\s+)#.*$')
EVIDENCE_VERSION = 1


def canonical(name):
    return re.sub(r'[-_.]+', '-', name).lower()


def logical_requirements(text):
    """A bounded exact-pin/hash subset; join before stripping pip-style comments."""
    pending = ''
    continuing = False
    start = 1
    for number, line in enumerate(text.splitlines(), 1):
        if not continuing:
            start = number
        comment = COMMENT.match(line)
        continuation = line.endswith('\\') and not comment
        if continuation and line.endswith('\\\\'):
            raise CommandError('Escaped requirement continuations are unsupported')
        pending += (' ' if comment else '') + (line[:-1] if continuation else line)
        if len(pending) > 64_000:
            raise CommandError('Logical requirement line exceeds the 64 KB limit')
        continuing = continuation
        if continuation:
            continue
        checked = Report('requirements-security')
        scan_text(checked, '(requirements)', pending)
        if checked.status != 'pass':
            raise CommandError('Python requirements contain potential credentials; resolve before auditing')
        yield start, COMMENT.sub('', pending).strip()
        pending = ''
    if continuing:
        raise CommandError('Requirements end with an incomplete continuation')


def requirements(repo, files):
    if not files:
        raise CommandError('Select at least one fully pinned requirements file')
    digest = hashlib.sha256()
    packages: dict[str, str] = {}
    for name in files:
        path = local_path(repo, name)
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise CommandError('Python requirements must be regular files')
            content = stream.read(2_000_001)
        if len(content) > 2_000_000:
            raise CommandError('Python requirements exceed the 2 MB size limit')
        checked = Report('requirements-security')
        scan_text(checked, '(requirements)', content.decode('utf-8-sig'))
        if checked.status != 'pass':
            raise CommandError('Python requirements contain potential credentials; resolve before auditing')
        digest.update(str(name).encode() + b'\0' + content + b'\0')
        for number, line in logical_requirements(content.decode('utf-8-sig')):
            if not line:
                continue
            tokens = line.split()
            match = PIN.fullmatch(tokens[0])
            if not match or any(not HASH.fullmatch(token) for token in tokens[1:]):
                raise CommandError(f'Requirements line {number} needs an exact name==version pin; '
                                   'only optional --hash=sha256 digests are supported after each pin')
            package, version = canonical(match[1]), match[2]
            if package in packages and packages[package] != version:
                raise CommandError('Requirements contain conflicting pins for the same package')
            packages[package] = version
    return digest.hexdigest(), packages


def parse_audit(data, expected):
    if isinstance(data, dict) and 'error' in data:
        raise CommandError('pip-audit returned an error')
    rows = data.get('dependencies') if isinstance(data, dict) else data
    if not isinstance(rows, list):
        raise CommandError('pip-audit returned an invalid dependency report')
    observed = {}
    findings = []
    for item in rows:
        if (not isinstance(item, dict) or not isinstance(item.get('name'), str)
                or not re.fullmatch(NAME, item['name']) or not isinstance(item.get('version'), str)
                or not isinstance(item.get('vulns'), list) or 'skip_reason' in item):
            raise CommandError('pip-audit skipped a dependency or returned invalid package evidence')
        name, version = canonical(item['name']), item['version']
        if name in observed or expected.get(name) != version:
            raise CommandError('pip-audit package evidence differs from the selected requirements')
        observed[name] = version
        for vulnerability in item['vulns']:
            if (not isinstance(vulnerability, dict) or not isinstance(vulnerability.get('id'), str)
                    or not re.fullmatch(r'[A-Za-z0-9._-]{1,200}', vulnerability['id'])
                    or not isinstance(vulnerability.get('fix_versions'), list)
                    or any(not isinstance(v, str) or not re.fullmatch(VERSION, v)
                           for v in vulnerability['fix_versions'])):
                raise CommandError('pip-audit returned invalid vulnerability evidence')
            fixes = vulnerability['fix_versions']
            remedy = 'Fixed versions: ' + ', '.join(fixes) if fixes else 'No fixed version reported'
            findings.append((name, f'{name} {version}: {vulnerability["id"]}. {remedy}.'))
    if observed != expected:
        raise CommandError('pip-audit did not audit every selected package')
    return findings


def audit_python(repo, files=None, executable='pip-audit', timeout=None):
    repo = Path(repo).resolve()
    files = files if files is not None else ['requirements.txt']
    report = Report('python-dependency-vulnerabilities')
    try:
        before, packages = requirements(repo, files)
        report.snapshot = before
        if packages:
            with tempfile.TemporaryDirectory(prefix='ai-pilled-python-audit-') as temporary:
                pins = Path(temporary) / 'requirements.txt'
                pins.write_text(''.join(f'{name}=={version}\n' for name, version in sorted(packages.items())))
                env = {k: v for k, v in os.environ.items()
                       if not k.startswith(('GIT_', 'PIP_', 'PYTHON'))}
                env.update(PIP_CONFIG_FILE=os.devnull, PIP_NO_INPUT='1', PYTHONDONTWRITEBYTECODE='1')
                completed = run_completed([executable, '--requirement', str(pins), '--no-deps', '--disable-pip',
                              '--strict', '--format', 'json', '--progress-spinner', 'off',
                              '--desc', 'off', '--aliases', 'off', '--vulnerability-service', 'pypi'],
                             repo, env=env, timeout=min(load(repo).timeout, timeout) if timeout else load(repo).timeout,
                             acceptable_codes=(0, 1))
                findings = parse_audit(loads(completed.stdout), packages)
                if completed.returncode != (1 if findings else 0):
                    raise CommandError('pip-audit exit status contradicts its vulnerability evidence')
        else:
            findings = []
        if requirements(repo, files)[0] != before:
            raise CommandError('Python dependency inputs changed during audit; rerun it')
        for name, message in findings:
            report.add('python-dependency-vulnerability', message, path=name)
        report.metrics = {'packages_audited': len(packages), 'vulnerabilities': len(findings),
                          'evidence_version': EVIDENCE_VERSION}
    except (CommandError, ValueError, OSError) as exc:
        report.add('python-dependency-audit-unavailable', str(exc) if isinstance(exc, CommandError)
                   else 'Cannot read a valid Python dependency audit', severity='warning')
    record(repo, report, 'python-dependency-audit')
    return report


def audit_python_changed(repo):
    """Reuse recent complete evidence only for unchanged explicitly selected pins."""
    from datetime import datetime, timezone
    from .runtime import Finding
    from .state import history

    repo = Path(repo)
    config = load(repo)
    try:
        fingerprint = requirements(repo, config.python_requirements)[0]
        for entry in reversed(history(repo)):
            if not isinstance(entry, dict) or entry.get('event') != 'python-dependency-audit':
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
            cached = Report('python-dependency-vulnerabilities', status=data['status'],
                            findings=findings, snapshot=fingerprint, metrics=data.get('metrics', {}))
            if requirements(repo, config.python_requirements)[0] == fingerprint:
                return cached, True
            break
    except (CommandError, ValueError, OSError, TypeError, KeyError):
        pass
    return audit_python(repo, config.python_requirements, config.python_audit_executable, timeout=30), False
