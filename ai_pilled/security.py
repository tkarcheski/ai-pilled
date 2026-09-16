"""Deterministic secret checks; semantic vulnerability review is a separate check."""
import hashlib
from pathlib import Path

from .runtime import CommandError, Report, run
from .python_security import inspect_python
from .credentials import PATTERNS


MAX_FILE_BYTES = 2_000_000


def scan_text(report, path, text):
    for number, line in enumerate(text.splitlines(), 1):
        for rule, pattern in PATTERNS:
            if pattern.search(line):
                report.add(rule, 'Potential credential detected; remove and rotate if genuine.',
                           path=path, line=number)


def scan_bytes(report, path, content):
    # A BOM identifies UTF-16/32 where ASCII tokens contain interleaved NULs.
    # Replacement decoding retains scannable prefixes even in malformed text.
    if content.startswith((b'\xff\xfe\x00\x00', b'\x00\x00\xfe\xff')):
        text = content.decode('utf-32', errors='replace')
    elif content.startswith((b'\xff\xfe', b'\xfe\xff')):
        text = content.decode('utf-16', errors='replace')
    else:
        text = content.decode('latin-1')
    scan_text(report, path, text)


def scan(repo, scope='staged', patterns=False):
    if scope not in ('staged', 'worktree'):
        raise ValueError('Unknown scan scope')
    root = Path(run(['git', 'rev-parse', '--show-toplevel'], repo).decode().strip())
    report = Report('security')
    digest = hashlib.sha256()
    if scope == 'staged':
        records = run(['git', 'ls-files', '--stage', '-z'], root).split(b'\0')
        sources = []
        for record in filter(None, records):
            metadata, raw_path = record.split(b'\t', 1)
            mode, oid, stage = metadata.split()
            path = raw_path.decode('utf-8', errors='surrogateescape')
            digest.update(record + b'\0')
            if stage != b'0':
                report.add('unmerged-index', 'Resolve index conflicts before validating.', path=path)
                continue
            if mode == b'160000':
                report.add('submodule-unscanned', 'Submodule content needs a separate scan.',
                           path=path, severity='warning')
                continue
            sources.append((path, oid.decode()))
    else:
        paths = run(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'], root)
        sources = [(p.decode('utf-8', errors='surrogateescape'), None)
                   for p in sorted(set(filter(None, paths.split(b'\0'))))]
    for path, oid in sources:
        try:
            if oid:
                size = int(run(['git', 'cat-file', '-s', oid], root))
                if size > MAX_FILE_BYTES:
                    raise CommandError('File exceeds scan size limit')
                content = run(['git', 'cat-file', 'blob', oid], root, limit=MAX_FILE_BYTES)
            else:
                file = root / path
                if file.is_symlink() or not file.resolve().is_relative_to(root.resolve()):
                    raise CommandError('Symlink content requires a separate scan')
                if not file.exists():
                    digest.update(path.encode(errors='surrogateescape') + b'\0deleted\0')
                    continue
                with file.open('rb') as stream:
                    content = stream.read(MAX_FILE_BYTES + 1)
                if len(content) > MAX_FILE_BYTES:
                    raise CommandError('File exceeds scan size limit')
                digest.update(path.encode(errors='surrogateescape') + b'\0')
                digest.update(hashlib.sha256(content).digest())
            scan_bytes(report, path, content)
            if patterns:
                inspect_python(report, path, content)
        except (CommandError, OSError) as exc:
            message = str(exc) if isinstance(exc, CommandError) else 'Unable to read file'
            report.add('scan-incomplete', message, path=path, severity='warning')
    report.snapshot = digest.hexdigest()
    return report
