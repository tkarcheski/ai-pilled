"""Bounded processes and structured, secret-free check results."""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass, field
from pathlib import Path
import os
import signal
import selectors
import time
import subprocess
import tempfile

from .credentials import redact_data


_ISOLATED_GIT = ContextVar('ai_pilled_isolated_git', default=False)


@contextmanager
def isolated_git():
    """Ignore inherited Git routing only inside disposable repository operations."""
    token = _ISOLATED_GIT.set(True)
    try:
        yield
    finally:
        _ISOLATED_GIT.reset(token)


MAX_FINDINGS = 100
SEVERITY_PRIORITY = {'info': 0, 'warning': 1, 'error': 2}


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
    metrics: dict[str, float] = field(default_factory=dict)

    def add(self, rule, message, *, path='', line=0, severity='error'):
        if severity == 'error':
            self.status = 'fail'
        elif severity != 'info' and self.status == 'pass':
            self.status = 'incomplete'
        if len(self.findings) >= MAX_FINDINGS:
            lowest = min(range(MAX_FINDINGS),
                         key=lambda i: SEVERITY_PRIORITY.get(self.findings[i].severity, 1))
            if SEVERITY_PRIORITY.get(severity, 1) > SEVERITY_PRIORITY.get(self.findings[lowest].severity, 1):
                self.findings[lowest] = Finding(rule, severity, message, path, line)
            if self.status == 'pass':
                self.status = 'incomplete'
            notice_severity = 'error' if self.status == 'fail' else 'warning'
            if len(self.findings) == MAX_FINDINGS:
                self.findings.append(Finding('findings-truncated', notice_severity,
                    'Additional findings omitted; resolve the displayed findings and rerun.'))
            elif self.findings[-1].rule == 'findings-truncated':
                self.findings[-1].severity = notice_severity
            return
        self.findings.append(Finding(rule, severity, message, path, line))

    def to_dict(self):
        return redact_data(asdict(self))


class CommandError(RuntimeError):
    pass


class CommandFailed(CommandError):
    """A completed subprocess with a known non-success exit code."""
    def __init__(self, executable, exit_code):
        self.exit_code = exit_code
        super().__init__(f'{Path(executable).name} exited with status {exit_code}')


class CommandUnavailable(CommandError):
    """No completed command result exists (missing executable or resource limit)."""


def run(argv, cwd, *, timeout=30, limit=2_000_000, env=None, input_data=None, acceptable_codes=(0,)):
    """Bound stdout + stderr while running and kill descendants on failure."""
    if timeout <= 0 or limit < 0:
        raise ValueError('timeout must be positive and limit nonnegative')
    # Replacement refs change local reads but not the original objects sent by push.
    if Path(argv[0]).name == 'git':
        argv = [argv[0], '--no-replace-objects', *argv[1:]]
        if _ISOLATED_GIT.get():
            env = {k: v for k, v in (os.environ if env is None else env).items()
                   if not k.startswith('GIT_')}
        # Legacy grafts alter ancestry independently of replacement refs.
        env = dict(os.environ if env is None else env)
        env['GIT_GRAFT_FILE'] = os.devnull
    with tempfile.TemporaryFile() as input_stream:
        if input_data is not None:
            input_stream.write(input_data)
            input_stream.seek(0)
        try:
            # Explicit configured argv is trusted; shell stays disabled and execution is bounded.
            child = subprocess.Popen(  # noqa: S603
                argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                stdin=input_stream if input_data is not None else subprocess.DEVNULL,
                start_new_session=True, env=env)
        except OSError as exc:
            raise CommandUnavailable(f'Cannot start {Path(argv[0]).name}: {exc.strerror}') from exc
        # PIPE is fixed above; this narrows types rather than enforcing a security boundary.
        assert child.stdout is not None and child.stderr is not None  # noqa: S101
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
                        raise CommandUnavailable(f'{Path(argv[0]).name} exceeded {timeout}s')
                    for key, _ in selector.select(min(remaining, 0.1)):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        total += len(chunk)
                        if total > limit:
                            raise CommandUnavailable(f'{Path(argv[0]).name} output exceeded {limit} bytes')
                        if key.data == 'stdout':
                            captured.extend(chunk)
                try:
                    code = child.wait(timeout=max(0.001, deadline - time.monotonic()))
                except subprocess.TimeoutExpired as exc:
                    raise CommandUnavailable(f'{Path(argv[0]).name} exceeded {timeout}s') from exc
                if code < 0:
                    raise CommandUnavailable(f'{Path(argv[0]).name} terminated by signal {-code}')
                if code not in acceptable_codes:
                    raise CommandFailed(argv[0], code)
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
