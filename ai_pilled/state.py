"""Local reports contain findings and outcomes, never source or tool transcripts."""
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import uuid

from .runtime import CommandError

MAX_HISTORY_BYTES = 2_000_000


def directory(repo):
    path = Path(repo) / '.ai-pilled'
    if path.is_symlink():
        raise CommandError('Refusing symlink state directory')
    path.mkdir(exist_ok=True)
    return path


def record(repo, report, event):
    path = directory(repo) / 'events.jsonl'
    flags = os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    entry = {'id': uuid.uuid4().hex, 'at': datetime.now(timezone.utc).isoformat(),
             'event': event, 'report': report.to_dict()}
    with os.fdopen(fd, 'r+', encoding='utf-8') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        if os.fstat(stream.fileno()).st_size > MAX_HISTORY_BYTES:
            stream.seek(0)
            records = stream.readlines()[-100:]
            stream.seek(0)
            stream.truncate()
            stream.writelines(records)
        stream.write(json.dumps(entry) + '\n')
        stream.flush()
    return entry


def history(repo):
    path = Path(repo) / '.ai-pilled' / 'events.jsonl'
    if not path.exists():
        return []
    if path.is_symlink() or path.parent.is_symlink():
        raise CommandError('Refusing symlink state files')
    with path.open() as stream:
        fcntl.flock(stream, fcntl.LOCK_SH)
        return [json.loads(line) for line in stream if line.strip()]
