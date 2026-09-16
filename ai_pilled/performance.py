"""Median process-duration budgets with explicit, local baseline updates."""
from datetime import datetime, timezone
import fcntl
from .locking import acquire_lock
import hashlib
import json
from .json_data import loads
import math
import os
import platform
import statistics
import stat
import time

from .file_io import read_regular
from .config import load
from .runtime import CommandError, Report, run
from .state import atomic_json, directory, record


def baseline_data(path):
    try:
        data = loads(read_regular(path, 10_000))
    except FileNotFoundError:
        return None
    if (not isinstance(data, dict) or type(data.get('version')) is not int or data['version'] != 1
            or type(data.get('median_seconds')) not in (int, float)
            or not math.isfinite(data['median_seconds']) or data['median_seconds'] <= 0
            or not isinstance(data.get('command_hash'), str)
            or not isinstance(data.get('host_hash'), str)):
        raise CommandError('Invalid performance baseline')
    return data


def benchmark(repo, runs=3, maximum_regression=20, save_baseline=False):
    report = Report('performance-baseline' if save_baseline else 'performance-regression')
    try:
        if type(runs) is not int or not 1 <= runs <= 10:
            raise CommandError('Benchmark runs must be between 1 and 10')
        if (type(maximum_regression) not in (int, float)
                or not math.isfinite(maximum_regression) or maximum_regression < 0):
            raise CommandError('Maximum regression must be a finite nonnegative percentage')
        config = load(repo)
        argv = config.commands.get('benchmark')
        if argv is None:
            raise CommandError('Configure commands.benchmark before measuring performance')
        command_hash = hashlib.sha256(json.dumps(argv).encode()).hexdigest()
        host_hash = hashlib.sha256(json.dumps((platform.node(), platform.machine(),
                                             platform.processor())).encode()).hexdigest()
        state = directory(repo)
        fd = os.open(state / 'benchmark.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        with os.fdopen(fd, 'rb') as lock:
            if not stat.S_ISREG(os.fstat(lock.fileno()).st_mode):
                raise CommandError('Performance lock must be a regular file')
            acquire_lock(lock, fcntl.LOCK_EX)
            path = state / 'benchmark.json'
            baseline = baseline_data(path)
            if not save_baseline:
                if baseline is None:
                    raise CommandError('No performance baseline; run benchmark --save-baseline first')
                if baseline['command_hash'] != command_hash or baseline['host_hash'] != host_hash:
                    raise CommandError('Benchmark command or host changed; record a new baseline explicitly')
            env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
            durations = []
            for _ in range(runs):
                start = time.perf_counter()
                run(argv, repo, timeout=config.timeout, env=env)
                duration = time.perf_counter() - start
                if not math.isfinite(duration) or duration <= 0:
                    raise CommandError('Benchmark timing must be finite and positive')
                durations.append(duration)
            median = statistics.median(durations)
            if not math.isfinite(median) or median <= 0:
                raise CommandError('Benchmark median must be finite and positive')
            report.metrics = {'median_seconds': median, 'runs': runs}
            report.snapshot = command_hash
            if save_baseline:
                atomic_json(path, {'version': 1, 'command_hash': command_hash, 'host_hash': host_hash,
                                   'median_seconds': median, 'runs': runs,
                                   'at': datetime.now(timezone.utc).isoformat()})
            else:
                change = (median / baseline['median_seconds'] - 1) * 100
                if not math.isfinite(change):
                    raise CommandError('Performance comparison overflowed; inspect the baseline before retrying')
                report.metrics.update(baseline_seconds=baseline['median_seconds'],
                                      regression_percent=change, maximum_regression_percent=maximum_regression)
                if change > maximum_regression:
                    report.add('performance-regression',
                               f'Median duration increased {change:.1f}%; budget is {maximum_regression:g}%.')
    except (CommandError, ValueError, OSError, OverflowError) as exc:
        report.add('performance-unavailable', str(exc) if isinstance(exc, CommandError)
                   else 'Cannot read or record performance evidence', severity='warning')
    record(repo, report, 'benchmark')
    return report
