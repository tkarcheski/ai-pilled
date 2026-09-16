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
    encoded = (json.dumps(entry) + '\n').encode('utf-8')
    if len(encoded) > MAX_HISTORY_BYTES:
        raise CommandError('Check record exceeds the local history size limit')
    path = directory(repo) / 'events.jsonl'
    flags = os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(path, flags, 0o600)
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
        if size + len(encoded) > MAX_HISTORY_BYTES:
            offset = max(0, size - MAX_HISTORY_BYTES)
            stream.seek(offset)
            content = stream.read(MAX_HISTORY_BYTES)
            if offset:
                # The bounded tail may begin inside a record; retain whole lines only.
                content = content.partition(b'\n')[2]
            records = content.splitlines(keepends=True)[-100:]
            retained = sum(map(len, records))
            while records and retained + len(encoded) > MAX_HISTORY_BYTES:
                retained -= len(records.pop(0))
            stream.seek(0)
            stream.truncate()
            stream.write(b''.join(records))
        stream.write(encoded)
        stream.flush()
    return entry


def history(repo):
    path = Path(repo) / '.ai-pilled' / 'events.jsonl'
    if path.is_symlink() or path.parent.is_symlink():
        raise CommandError('Refusing symlink state files')
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
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


def atomic_text(path, text, mode=0o600, *, before_publish=None, exclusive=False):
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


def atomic_json(path, data):
    atomic_text(path, json.dumps(data, indent=2) + '\n')
