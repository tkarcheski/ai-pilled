"""Deterministic secret checks; semantic vulnerability review is a separate check."""
import ast
import hashlib
import os
import stat

from .git_blobs import read_blobs
from .runtime import CommandError, Report, run, git_path
from .python_security import inspect_python, parse_python
from .credentials import PATTERNS, json_secret_literals


MAX_FILE_BYTES = 2_000_000


def scan_text(report, path, text):
    for number, line in enumerate(text.splitlines(), 1):
        for rule, pattern in PATTERNS:
            if pattern.search(line):
                report.add(rule, 'Potential credential detected; remove and rotate if genuine.',
                           path=path, line=number)

    seen = {(finding.rule, finding.path, finding.line) for finding in report.findings}
    for _, _, number, decoded, secret_field in json_secret_literals(text):
        for rule, pattern in PATTERNS:
            if (rule, path, number) not in seen and (pattern.search(decoded)
                    or rule == 'aws-secret-key' and secret_field):
                report.add(rule, 'Potential credential detected in an encoded string; remove and rotate if genuine.',
                           path=path, line=number)
                seen.add((rule, path, number))


def scan_path(report, path):
    for rule, pattern in PATTERNS:
        if pattern.search(path):
            report.add(rule, 'Potential credential detected in a file name; rename and rotate if genuine.',
                       path=path)


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
    if path.endswith('.py'):
        try:
            tree = parse_python(content, path)
        except (SyntaxError, ValueError, RecursionError):
            report.add('python-literals-unparsed', 'Python string literals could not be inspected by this interpreter.',
                       path=path, severity='warning')
            return
        seen = {(finding.rule, finding.path, finding.line) for finding in report.findings}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, (str, bytes)):
                continue
            value = node.value.decode('latin-1') if isinstance(node.value, bytes) else node.value
            if len(value) < 20:  # Shortest recognizable credential is an AWS access-key ID.
                continue
            decoded = Report('literal-security')
            scan_text(decoded, path, value)
            for finding in decoded.findings:
                key = (finding.rule, path, node.lineno)
                if key not in seen:
                    report.add(finding.rule, 'Potential credential in a Python literal; remove and rotate if genuine.',
                               path=path, line=node.lineno, severity=finding.severity)
                    seen.add(key)


def scan(repo, scope='staged', patterns=False):
    if scope not in ('staged', 'worktree'):
        raise ValueError('Unknown scan scope')
    root = git_path(run(['git', 'rev-parse', '--show-toplevel'], repo))
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
    if scope == 'staged':
        for path, content, error in read_blobs(root, sources, MAX_FILE_BYTES):
            scan_path(report, path)
            if error is not None:
                report.add('scan-incomplete', error, path=path, severity='warning')
            else:
                scan_bytes(report, path, content)
                if patterns:
                    inspect_python(report, path, content)
        report.snapshot = digest.hexdigest()
        return report
    for path, _ in sources:
        scan_path(report, path)
        try:
            file = root / path
            if file.is_symlink() or not file.resolve().is_relative_to(root.resolve()):
                raise CommandError('Symlink content requires a separate scan')
            if not file.exists():
                digest.update(path.encode(errors='surrogateescape') + b'\0deleted\0')
                continue
            fd = os.open(file, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            with os.fdopen(fd, 'rb') as stream:
                mode = os.fstat(stream.fileno()).st_mode
                if not stat.S_ISREG(mode):
                    raise CommandError('Only regular files can be scanned')
                content = stream.read(MAX_FILE_BYTES + 1)
            if len(content) > MAX_FILE_BYTES:
                raise CommandError('File exceeds scan size limit')
            digest.update(path.encode(errors='surrogateescape') + b'\0')
            digest.update(str(stat.S_IMODE(mode)).encode() + b'\0')
            digest.update(hashlib.sha256(content).digest())
            scan_bytes(report, path, content)
            if patterns:
                inspect_python(report, path, content)
        except (CommandError, OSError) as exc:
            message = str(exc) if isinstance(exc, CommandError) else 'Unable to read file'
            report.add('scan-incomplete', message, path=path, severity='warning')
    report.snapshot = digest.hexdigest()
    return report
