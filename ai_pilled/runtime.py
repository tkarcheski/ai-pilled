"""Bounded processes and structured, secret-free check results."""
from dataclasses import asdict, dataclass, field
from pathlib import Path
import os
import signal
import subprocess
import tempfile


@dataclass
class Finding:
    rule: str
    severity: str
    message: str
    path: str = ''
    line: int = 0


@dataclass
class Report:
    check: str
    status: str = 'pass'
    findings: list[Finding] = field(default_factory=list)
    snapshot: str = ''

    def add(self, rule, message, *, path='', line=0, severity='error'):
        self.findings.append(Finding(rule, severity, message, path, line))
        if severity == 'error':
            self.status = 'fail'
        elif self.status == 'pass':
            self.status = 'incomplete'

    def to_dict(self):
        return asdict(self)


class CommandError(RuntimeError):
    pass


def run(argv, cwd, *, timeout=30, limit=2_000_000, env=None):
    """Never invoke a shell; kill the process group on timeout; cap captured data."""
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            child = subprocess.Popen(argv, cwd=cwd, stdout=stdout, stderr=stderr,
                                     stdin=subprocess.DEVNULL, start_new_session=True, env=env)
        except OSError as exc:
            raise CommandError(f'Cannot start {Path(argv[0]).name}: {exc.strerror}') from exc
        try:
            code = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
            raise CommandError(f'{Path(argv[0]).name} exceeded {timeout}s') from exc
        size = stdout.tell()
        if size > limit:
            raise CommandError(f'{Path(argv[0]).name} output exceeded {limit} bytes')
        if code:
            # Tool output may contain source, credentials, URLs, or environment values.
            raise CommandError(f'{Path(argv[0]).name} exited with status {code}')
        stdout.seek(0)
        return stdout.read()
