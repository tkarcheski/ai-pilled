"""Local reports contain findings and outcomes, never source or tool transcripts."""
from datetime import datetime, timezone
import fcntl
from .locking import acquire_lock
import json
from .json_data import loads
import os
import stat
from pathlib import Path
import uuid
import tempfile

from .file_io import directory_beneath
from .runtime import CommandError

MAX_HISTORY_BYTES = 2_000_000


def directory(repo):
    path = Path(repo) / '.ai-pilled'
    if path.is_symlink():
        raise CommandError('Refusing symlink state directory')
    path.mkdir(exist_ok=True)
    return path


def record(repo, report, event):
    entry = {'id': uuid.uuid4().hex, 'at': datetime.now(timezone.utc).isoformat(),
             'event': event, 'report': report.to_dict()}
    try:
        encoded = (json.dumps(entry, allow_nan=False) + '\n').encode('utf-8')
    except ValueError as exc:
        raise CommandError('Check records require finite JSON numbers') from exc
    if len(encoded) > MAX_HISTORY_BYTES:
        raise CommandError('Check record exceeds the local history size limit')
    try:
        loads(encoded)
    except ValueError as exc:
        raise CommandError('Check record exceeds history JSON constraints') from exc
    root = Path(repo).resolve()
    directory(root)
    flags = os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK
    with directory_beneath(root, '.ai-pilled') as parent:
        fd = os.open('events.jsonl', flags, 0o600, dir_fd=parent)
    with os.fdopen(fd, 'r+b') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise CommandError('Local history must be a regular file')
        acquire_lock(stream, fcntl.LOCK_EX)
        metadata = os.fstat(stream.fileno())
        if metadata.st_nlink != 1:
            raise CommandError('Local history must have exactly one hard link')
        # This descriptor is a private history file, never a shared inode or symlink.
        os.fchmod(stream.fileno(), 0o600)
        size = metadata.st_size
        separator = b''
        if size:
            stream.seek(-1, os.SEEK_END)
            if stream.read(1) != b'\n':
                offset = max(0, size - MAX_HISTORY_BYTES)
                stream.seek(offset)
                tail = stream.read(MAX_HISTORY_BYTES)
                if offset and b'\n' not in tail and b'\r' not in tail:
                    raise CommandError('Unterminated history record exceeds the size limit; inspect before appending')
                lines = tail.splitlines()
                final = lines[-1] if lines else b''
                try:
                    if final.strip():
                        loads(final)
                except ValueError as exc:
                    raise CommandError('Local history ends with incomplete JSON; inspect before appending') from exc
                separator = b'\n'
        if size + len(separator) + len(encoded) > MAX_HISTORY_BYTES:
            offset = max(0, size - MAX_HISTORY_BYTES)
            stream.seek(offset)
            content = stream.read(MAX_HISTORY_BYTES)
            records = content.splitlines(keepends=True)
            if offset:
                # The bounded tail may begin inside a record; retain whole lines only.
                records = records[1:]
            records = records[-100:]
            if separator and records:
                records[-1] += b'\n'
            retained = sum(map(len, records))
            while records and retained + len(encoded) > MAX_HISTORY_BYTES:
                retained -= len(records.pop(0))
            stream.seek(0)
            stream.truncate()
            stream.write(b''.join(records))
            separator = b''
        stream.write(separator + encoded)
        stream.flush()
    return entry


def history(repo):
    root = Path(repo).resolve()
    path = root / '.ai-pilled' / 'events.jsonl'
    if path.is_symlink() or path.parent.is_symlink():
        raise CommandError('Refusing symlink state files')
    try:
        with directory_beneath(root, '.ai-pilled') as parent:
            fd = os.open('events.jsonl', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    except FileNotFoundError:
        return []
    with os.fdopen(fd, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise CommandError('Local history must be a regular file')
        acquire_lock(stream, fcntl.LOCK_SH)
        if os.fstat(stream.fileno()).st_nlink != 1:
            raise CommandError('Local history must have exactly one hard link')
        content = stream.read(MAX_HISTORY_BYTES + 1)
        if len(content) > MAX_HISTORY_BYTES:
            raise CommandError('Local history exceeds the size limit; archive it before reading')
        return [loads(line) for line in content.splitlines() if line.strip()]


def atomic_text(path, text, mode=0o600, *, before_publish=None, exclusive=False, root=None):
    if root is not None:
        return atomic_text_beneath(root, path.relative_to(root), text, mode,
                                   before_publish=before_publish, exclusive=exclusive)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(text)
            os.fchmod(stream.fileno(), mode)
            metadata = os.fstat(stream.fileno())
        if before_publish is not None:
            before_publish()
        if exclusive:
            os.link(temporary, path)
        else:
            os.replace(temporary, path)
        return metadata.st_dev, metadata.st_ino
    finally:
        temporary.unlink(missing_ok=True)


def atomic_text_beneath(root, relative, text, mode=0o600, *, before_publish=None, exclusive=False):
    return atomic_bytes_beneath(root, relative, text.encode('utf-8'), mode,
                                before_publish=before_publish, exclusive=exclusive)


def atomic_bytes_beneath(root, relative, content, mode=0o600, *, before_publish=None, exclusive=False):
    """Create and publish bytes through one anchored parent, including cleanup."""
    relative = Path(relative)
    if relative.is_absolute() or '..' in relative.parts or not relative.parts:
        raise CommandError('Output path must stay beneath its root')
    with directory_beneath(root, relative.parent, create=True) as parent:
        temporary = '.ai-pilled-' + uuid.uuid4().hex + '.tmp'
        descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                             0o600, dir_fd=parent)
        try:
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(content)
                os.fchmod(stream.fileno(), mode)
                metadata = os.fstat(stream.fileno())
            if before_publish is not None:
                before_publish()
            if exclusive:
                os.link(temporary, relative.name, src_dir_fd=parent, dst_dir_fd=parent)
            else:
                os.replace(temporary, relative.name, src_dir_fd=parent, dst_dir_fd=parent)
            return metadata.st_dev, metadata.st_ino
        finally:
            try:
                os.unlink(temporary, dir_fd=parent)
            except FileNotFoundError:
                pass


def atomic_json(path, data, *, root=None):
    atomic_text(path, json.dumps(data, indent=2) + '\n', root=root)
