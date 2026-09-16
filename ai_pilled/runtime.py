"""Bounded processes and structured, secret-free check results."""
from dataclasses import asdict, dataclass, field
from pathlib import Path
import os
import signal
import selectors
import time
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


def run(argv, cwd, *, timeout=30, limit=2_000_000, env=None, input_data=None, acceptable_codes=(0,)):
    """Bound stdout + stderr while running and kill descendants on failure."""
    if timeout <= 0 or limit < 0:
        raise ValueError('timeout must be positive and limit nonnegative')
    with tempfile.TemporaryFile() as input_stream:
        if input_data is not None:
            input_stream.write(input_data)
            input_stream.seek(0)
        try:
            child = subprocess.Popen(
                argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                stdin=input_stream if input_data is not None else subprocess.DEVNULL,
                start_new_session=True, env=env)
        except OSError as exc:
            raise CommandError(f'Cannot start {Path(argv[0]).name}: {exc.strerror}') from exc
        deadline = time.monotonic() + timeout
        captured = bytearray()
        total = 0
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ, 'stdout')
                selector.register(child.stderr, selectors.EVENT_READ, 'stderr')
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise CommandError(f'{Path(argv[0]).name} exceeded {timeout}s')
                    for key, _ in selector.select(min(remaining, 0.1)):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        total += len(chunk)
                        if total > limit:
                            raise CommandError(f'{Path(argv[0]).name} output exceeded {limit} bytes')
                        if key.data == 'stdout':
                            captured.extend(chunk)
                try:
                    code = child.wait(timeout=max(0.001, deadline - time.monotonic()))
                except subprocess.TimeoutExpired as exc:
                    raise CommandError(f'{Path(argv[0]).name} exceeded {timeout}s') from exc
                if code not in acceptable_codes:
                    raise CommandError(f'{Path(argv[0]).name} exited with status {code}')
                return bytes(captured)
        except BaseException:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
            raise
        finally:
            child.stdout.close()
            child.stderr.close()
