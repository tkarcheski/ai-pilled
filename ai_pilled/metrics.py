"""Explicit coverage-report and built-artifact budget checks."""
import hashlib
from .json_data import loads
import math
import os
import stat
from pathlib import Path

from .file_io import open_regular, read_regular
from .runtime import CommandError, Report
from .state import record


MAX_ARTIFACT_ENTRIES = 10_000


def local_path(repo, name):
    root = Path(repo).resolve()
    relative = Path(name)
    if relative.is_absolute() or '..' in relative.parts or not relative.parts:
        raise CommandError('Measurement path must stay inside the repository')
    candidate = root
    for part in relative.parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise CommandError('Measurement paths must not contain symlinks')
    return candidate


def coverage(repo, source, minimum):
    report = Report('coverage-budget')
    try:
        if not math.isfinite(minimum) or not 0 <= minimum <= 100:
            raise CommandError('Coverage minimum must be between 0 and 100')
        path = local_path(repo, source)
        content = read_regular(path, 2_000_000)
        data = loads(content)
        if not isinstance(data, dict) or not isinstance(data.get('totals'), dict):
            raise CommandError('Expected a coverage.py JSON report with totals')
        totals = data['totals']
        covered, total = totals.get('covered_lines'), totals.get('num_statements')
        if type(covered) is not int or type(total) is not int or not 0 <= covered <= total or total == 0:
            raise CommandError('Coverage report has invalid or empty line counts')
        percent = covered / total * 100
        report.metrics = {'covered_lines': covered, 'total_lines': total,
                          'line_percent': percent, 'minimum_percent': minimum}
        report.snapshot = hashlib.sha256(content).hexdigest()
        if percent < minimum:
            report.add('coverage-below-budget', f'Line coverage {percent:.2f}% is below {minimum:g}%.',
                       path=str(source))
    except (CommandError, ValueError, OSError) as exc:
        report.add('coverage-unavailable', str(exc) if isinstance(exc, CommandError)
                   else 'Cannot read a valid coverage report', severity='warning')
    record(repo, report, 'coverage-budget')
    return report


def artifact_files(path):
    """Bound traversal and propagate every directory-read failure."""
    pending, files = [path], []
    count = 1  # Include the selected root, even when it is an empty directory.
    while pending:
        item = pending.pop()
        mode = item.lstat().st_mode
        if stat.S_ISLNK(mode):
            raise CommandError('Build artifact contains a symlink')
        if stat.S_ISDIR(mode):
            with os.scandir(item) as children:
                for child in children:
                    count += 1
                    if count > MAX_ARTIFACT_ENTRIES:
                        raise CommandError('Build artifacts exceed the 10000-entry traversal limit')
                    pending.append(item / child.name)
        else:
            files.append(item)
    return sorted(files)


def bundle(repo, source, maximum):
    report = Report('bundle-budget')
    try:
        if type(maximum) is not int or maximum < 0:
            raise CommandError('Bundle maximum must be a nonnegative byte count')
        path = local_path(repo, source)
        if not path.exists():
            raise CommandError('Build artifact is missing; build before measuring')
        paths = artifact_files(path)
        digest = hashlib.sha256()
        total = files = 0
        for item in paths:
            if item.is_symlink():
                raise CommandError('Build artifact contains a symlink')
            files += 1
            digest.update(str(item.relative_to(Path(repo).resolve())).encode(errors='surrogateescape') + b'\0')
            with open_regular(item) as stream:
                digest.update(str(os.fstat(stream.fileno()).st_size).encode() + b'\0')
                while chunk := stream.read(65536):
                    total += len(chunk)
                    if total > 100_000_000:
                        raise CommandError('Build artifacts exceed the 100 MB measurement limit')
                    digest.update(chunk)
        if not files:
            raise CommandError('Build artifact directory is empty')
        report.metrics = {'bytes': total, 'files': files, 'maximum_bytes': maximum}
        report.snapshot = digest.hexdigest()
        if total > maximum:
            report.add('bundle-over-budget', f'Build artifacts total {total} bytes; budget is {maximum}.',
                       path=str(source))
    except (CommandError, OSError) as exc:
        report.add('bundle-unavailable', str(exc) if isinstance(exc, CommandError)
                   else 'Cannot read build artifacts', severity='warning')
    record(repo, report, 'bundle-budget')
    return report
