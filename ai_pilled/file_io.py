"""Bounded reads of regular input files without following the final symlink."""
from contextlib import contextmanager
import os
import stat

from .runtime import CommandError


@contextmanager
def open_regular(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise CommandError('Input must be a regular file')
        yield stream


def read_regular(path, maximum):
    with open_regular(path) as stream:
        content = stream.read(maximum + 1)
    if len(content) > maximum:
        raise CommandError('Input exceeds the configured size limit')
    return content


def file_identity(metadata):
    """Metadata identity excluding access time, which reads may update."""
    return (metadata.st_dev, metadata.st_ino, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns, metadata.st_mode)


def read_snapshot(path, maximum):
    """Read bounded bytes plus descriptor identity, distinguishing an absent file."""
    try:
        with open_regular(path) as stream:
            before = file_identity(os.fstat(stream.fileno()))
            content = stream.read(maximum + 1)
            after = file_identity(os.fstat(stream.fileno()))
    except FileNotFoundError:
        return None, None
    if len(content) > maximum:
        raise CommandError('Input exceeds the configured size limit')
    if before != after:
        raise CommandError('Input changed while reading; rerun after reviewing edits')
    return content, after
