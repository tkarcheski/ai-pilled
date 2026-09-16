"""Explicit coverage-report and built-artifact budget checks."""
from fractions import Fraction
import hashlib
from .json_data import loads
import math
import os
import stat
from pathlib import Path

from .file_io import file_identity, open_beneath, read_beneath
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
        if type(minimum) not in (int, float) or not 0 <= minimum <= 100 or not math.isfinite(minimum):
            raise CommandError('Coverage minimum must be between 0 and 100')
        root = Path(repo).resolve()
        path = local_path(root, source)
        content = read_beneath(root, path.relative_to(root), 2_000_000)
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
        # Compare exact line counts to the threshold's decimal representation.
        # A rounded display percentage must never decide acceptance.
        threshold = Fraction(str(minimum))
        if covered * 100 * threshold.denominator < total * threshold.numerator:
            report.add('coverage-below-budget', f'Line coverage {percent:.2f}% is below {minimum:g}%.',
                       path=str(source))
    except (CommandError, ValueError, OSError) as exc:
        report.add('coverage-unavailable', str(exc) if isinstance(exc, CommandError)
                   else 'Cannot read a valid coverage report', severity='warning')
    record(repo, report, 'coverage-budget')
    return report


def artifact_files(path):
    """Return files and all entry identities; bound traversal and propagate failures."""
    pending, files = [path], []
    identities = {}
    count = 1  # Include the selected root, even when it is an empty directory.
    while pending:
        item = pending.pop()
        metadata = item.lstat()
        identities[item] = file_identity(metadata)
        mode = metadata.st_mode
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
    return sorted(files), identities


def bundle(repo, source, maximum):
    report = Report('bundle-budget')
    try:
        if type(maximum) is not int or maximum < 0:
            raise CommandError('Bundle maximum must be a nonnegative byte count')
        root = Path(repo).resolve()
        path = local_path(root, source)
        if not path.exists():
            raise CommandError('Build artifact is missing; build before measuring')
        paths, identities = artifact_files(path)
        digest = hashlib.sha256()
        total = files = 0
        for item in paths:
            if item.is_symlink():
                raise CommandError('Build artifact contains a symlink')
            files += 1
            relative = item.relative_to(root)
            digest.update(str(relative).encode(errors='surrogateescape') + b'\0')
            with open_beneath(root, relative) as stream:
                metadata = os.fstat(stream.fileno())
                if file_identity(metadata) != identities[item]:
                    raise CommandError('Build artifact changed before reading; finish the build and rerun')
                digest.update(str(metadata.st_size).encode() + b'\0')
                while chunk := stream.read(65536):
                    total += len(chunk)
                    if total > 100_000_000:
                        raise CommandError('Build artifacts exceed the 100 MB measurement limit')
                    digest.update(chunk)
                if file_identity(os.fstat(stream.fileno())) != identities[item]:
                    raise CommandError('Build artifact changed during reading; finish the build and rerun')
        if artifact_files(path) != (paths, identities):
            raise CommandError('Build artifact inventory changed during measurement; finish the build and rerun')
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
